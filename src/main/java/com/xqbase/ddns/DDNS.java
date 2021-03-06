package com.xqbase.ddns;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.json.JSONException;
import org.json.JSONObject;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.xqbase.metric.client.ManagementMonitor;
import com.xqbase.metric.client.MetricClient;
import com.xqbase.metric.common.Metric;
import com.xqbase.util.ByteArrayQueue;
import com.xqbase.util.Bytes;
import com.xqbase.util.Conf;
import com.xqbase.util.Log;
import com.xqbase.util.Numbers;
import com.xqbase.util.Runnables;
import com.xqbase.util.Service;
import com.xqbase.util.http.HttpPool;

class DataEntry {
	SocketAddress addr;
	byte[] data;

	DataEntry(SocketAddress addr, byte[] data) {
		this.addr = addr;
		this.data = data;
	}
}

interface Builder {
	Record build(Name origin, String target) throws IOException;
}

public class DDNS {
	private static final Record[] EMPTY_RECORDS = new Record[0];
	private static HashMap<String, Builder> builderMap = new HashMap<>();
	private static HashMap<Integer, HashMap<String, Record[]>>
			recordsMap = new HashMap<>();
	private static volatile HashMap<String, Record[]>
			aApiRecords = new HashMap<>();
	private static ConcurrentHashMap<String, Record[]>
			aDynamics = new ConcurrentHashMap<>();
	private static HashMap<String, Record[]>
			aRecords = new HashMap<>(), aWildcards = new HashMap<>(),
			nsRecords = new HashMap<>(), mxRecords = new HashMap<>(),
			soaRecords = new HashMap<>(), txtRecords = new HashMap<>(),
			ptrRecords = new HashMap<>();
	private static ArrayList<InetSocketAddress> forwards = new ArrayList<>();
	private static LinkedBlockingQueue<DataEntry>
			dataQueue = new LinkedBlockingQueue<>();
	private static Service service = new Service();
	private static HashMap<String, Integer> countMap = new HashMap<>();
	private static long propAccessed = 0, dosAccessed = 0;
	private static int propPeriod, dosPeriod, dosRequests, staticTtl, mxPriority;
	private static Name soaAdmin;
	private static boolean verbose = false;
	private static volatile boolean needWriteBack = false;

	static {
		builderMap.put("ns", (origin, target) -> new NSRecord(origin,
				DClass.IN, staticTtl, new Name(target)));
		builderMap.put("mx", (origin, target) -> new MXRecord(origin,
				DClass.IN, staticTtl, mxPriority, new Name(target)));
		builderMap.put("soa", (origin, target) -> new SOARecord(origin,
				DClass.IN, staticTtl, new Name(target),
				soaAdmin, 1, staticTtl, staticTtl, staticTtl, staticTtl));
		builderMap.put("txt", (origin, target) -> new TXTRecord(origin,
				DClass.IN, staticTtl, target));
		recordsMap.put(Integer.valueOf(Type.NS), nsRecords);
		recordsMap.put(Integer.valueOf(Type.MX), mxRecords);
		recordsMap.put(Integer.valueOf(Type.SOA), soaRecords);
		recordsMap.put(Integer.valueOf(Type.TXT), txtRecords);
		recordsMap.put(Integer.valueOf(Type.PTR), ptrRecords);
	}

	private static void updateRecords(Map<String, Record[]> records,
			String host, String value, int ttl,
			Map<String, ArrayList<Record>> ptrRecordMap) throws IOException {
		if (value == null) {
			records.remove(host);
			return;
		}
		Name origin = new Name((host.endsWith(".") ? host : host + "."));
		ArrayList<Record> recordList = new ArrayList<>();
		for (String s : value.split("[,;]")) {
			if (s.matches(".*[A-Z|a-z].*")) {
				CNAMERecord record = new CNAMERecord(origin, DClass.IN, ttl,
						new Name(s.endsWith(".") ? s : s + "."));
				recordList.add(record);
				continue;
			}
			String[] ss = s.split("\\.");
			if (ss.length < 4) {
				continue;
			}
			byte[] ip = new byte[4];
			for (int i = 0; i < 4; i ++) {
				ip[i] = (byte) Numbers.parseInt(ss[i]);
			}
			recordList.add(new ARecord(origin, DClass.IN,
					ttl, InetAddress.getByAddress(ip)));
			if (ptrRecordMap != null) {
				StringBuilder sb = new StringBuilder();
				for (int i = 3; i >= 0; i --) {
					sb.append(ip[i] & 0xFF).append('.');
				}
				String ipAddr = sb + "in-addr.arpa";
				ptrRecordMap.computeIfAbsent(ipAddr, key -> new ArrayList<>()).
						add(new PTRRecord(new Name(ipAddr + "."), DClass.IN, ttl, origin));
			}
		}
		records.put(host, recordList.toArray(EMPTY_RECORDS));
	}

	private static HashMap<String, String> getDynamicMap() {
		HashMap<String, String> dynamicMap = new HashMap<>();
		aDynamics.forEach((host, records) -> {
			StringBuilder sb = new StringBuilder();
			for (Record record : records) {
				if (record instanceof ARecord) {
					sb.append(((ARecord) record).getAddress().getHostAddress());
				} else if (record instanceof CNAMERecord) {
					sb.append(((CNAMERecord) record).getTarget().
							toString(true).toLowerCase());
				}
				sb.append(',');
			}
			dynamicMap.put(host, sb.substring(0, Math.max(sb.length() - 1, 0)));
		});
		return dynamicMap;
	}

	private static void updateFromApi(HttpPool addrApi,
			Map<String, List<String>> addrApiAuth, int ttl) {
		ByteArrayQueue body = new ByteArrayQueue();
		try {
			if (addrApi.get("", addrApiAuth, body, null) >= 400) {
				Log.w(body.toString());
				return;
			}
		} catch (IOException e) {
			Log.e(e);
			return;
		}
		try {
			HashMap<String, Record[]> apiRecords_ = new HashMap<>();
			JSONObject map = new JSONObject(body.toString());
			Iterator<?> it = map.keys();
			while (it.hasNext()) {
				String host = (String) it.next();
				String addr = map.optString(host);
				if (addr != null) {
					updateRecords(apiRecords_, host, addr, ttl, null);
				}
			}
			aApiRecords = apiRecords_;
		} catch (IOException | JSONException e) {
			Log.e(e);
		}
	}

	private static void loadProp() {
		aRecords.clear();
		aWildcards.clear();
		nsRecords.clear();
		mxRecords.clear();
		soaRecords.clear();
		txtRecords.clear();
		Properties p = Conf.load("DDNS");
		verbose = Conf.getBoolean(p.getProperty("verbose"), false);
		staticTtl = Numbers.parseInt(p.getProperty("ttl.static"), 3600);
		mxPriority = Numbers.parseInt(p.getProperty("priority.mx"), 10);
		HashMap<String, ArrayList<Record>> ptrRecordMap = new HashMap<>();
		p.forEach((k, v) -> {
			String key = (String) k;
			String value = (String) v;
			int underscore = key.indexOf('_');
			if (underscore < 0) {
				return;
			}
			String type = key.substring(0, underscore);
			String host = key.substring(underscore + 1);
			try {
				if (type.equals("a")) {
					if (host.startsWith("*.")) {
						updateRecords(aWildcards, host.substring(2), value, staticTtl, null);
					} else {
						updateRecords(aRecords, host, value, staticTtl, ptrRecordMap);
					}
					return;
				}
				Builder constructor = builderMap.get(type);
				if (constructor == null) {
					return;
				}
				Name origin = new Name(host.endsWith(".") ? host : host + ".");
				ArrayList<Record> records = new ArrayList<>();
				for (String target : value.split("[,;]")) {
					records.add(constructor.build(origin,
							(type.equals("txt") || target.endsWith(".")) ?
							target : target + "."));
				}
				if (!records.isEmpty()) {
					recordsMap.get(Type.class.getField(type.toUpperCase()).get(null)).
							put(host, records.toArray(EMPTY_RECORDS));
				}
			} catch (IOException | ReflectiveOperationException e) {
				Log.e(e);
			}
		});
		ptrRecords.clear();
		ptrRecordMap.forEach((host, records) -> {
			ptrRecords.put(host, records.toArray(EMPTY_RECORDS));
		});
	}

	private static boolean blocked(String ip) {
		if (dosPeriod == 0 || dosRequests == 0) {
			return false;
		}
		long now = System.currentTimeMillis();
		if (now > dosAccessed + dosPeriod) {
			countMap.clear();
			dosAccessed = now;
		}
		Integer count_ = countMap.get(ip);
		int count = (count_ == null ? 0 : count_.intValue());
		count ++;
		countMap.put(ip, Integer.valueOf(count));
		if (count < dosRequests) {
			// Remote IP Blocked
			return false;
		}
		if (count % dosRequests == 0) {
			Log.w("DoS Attack from " + ip + ", requests = " + count);
		}
		return true;
	}

	private static void dump(DatagramPacket packet, boolean send) {
		if (!verbose) {
			return;
		}
		StringWriter sw = new StringWriter();
		PrintWriter out = new PrintWriter(sw);
		out.println((send ? "Sent to " : "Received from ") +
				packet.getAddress().getHostAddress());
		byte[] data = Bytes.sub(packet.getData(), packet.getOffset(), packet.getLength());
		Bytes.dump(out, data);
		try {
			out.println(new Message(data));
		} catch (IOException e) {
			out.println(e.getMessage());
		}
		Log.d(sw.toString());
	}

	private static Record[] resolveWildcard(Map<String, Record[]>
			wildcards, String host, String[] domain) {
		String host_ = host;
		Record[] records = wildcards.get(host_);
		while (records == null) {
			int dot = host_.indexOf('.');
			if (dot < 0) {
				break;
			}
			host_ = host_.substring(dot + 1);
			if (host_.isEmpty()) {
				break;
			}
			records = wildcards.get(host_);
		}
		if (records != null && domain[0] == null) {
			domain[0] = "*." + host_;
		}
		return records;
	}

	private static Message service(Message request, String[] domain) {
		// Check Request Validity
		Header header = request.getHeader();
		if (header.getFlag(Flags.QR)) {
			return null;
		}
		if (header.getRcode() != Rcode.NOERROR) {
			header.setRcode(Rcode.FORMERR);
			return request;
		}
		if (header.getOpcode() != Opcode.QUERY) {
			header.setRcode(Rcode.NOTIMP);
			return request;
		}
		header.setFlag(Flags.QR);
		Record question = request.getQuestion();
		if (question == null) {
			header.setRcode(Rcode.FORMERR);
			return request;
		}
		Name name = question.getName();
		if (name == null) {
			header.setRcode(Rcode.FORMERR);
			return request;
		}
		String host = name.toString(true).toLowerCase();
		// Get ANSWER Records
		Record[] answers;
		int type = question.getType();
		switch (type) {
		case Type.A:
		case Type.AAAA:
		case Type.CNAME:
		case Type.ANY:
			answers = aRecords.get(host);
			if (answers != null) {
				domain[0] = host;
				break;
			}
			answers = resolveWildcard(aWildcards, host, domain);
			if (answers == null || answers.length == 0) {
				// Records from Addr-Api is Preferred
				answers = aApiRecords.get(host);
				if (answers == null || answers.length == 0) {
					answers = aDynamics.get(host);
				}
				break;
			}
			// Set name for wildcard
			try {
				name = new Name(host.endsWith(".") ? host : host + ".");
			} catch (IOException e) {
				Log.w("Unrecognized host \"" + host + "\": " + e.getMessage());
				break;
			}
			// Do not pollute "aWildcards"
			Record[] cloned = new Record[answers.length];
			for (int i = 0; i < answers.length; i ++) {
				Record record = answers[i];
				int dclass = record.getDClass();
				long ttl = record.getTTL();
				if (record instanceof ARecord) {
					cloned[i] = new ARecord(name, dclass, ttl,
							((ARecord) record).getAddress());
				} else if (record instanceof CNAMERecord) {
					cloned[i] = new CNAMERecord(name, dclass, ttl,
							((CNAMERecord) record).getTarget());
				} else {
					Log.e("Not A or CNAME: " + answers[i]);
					cloned[i] = answers[i];
				}
			}
			answers = cloned;
			break;
		case Type.CAA:
			answers = null;
			break;
		default:
			HashMap<String, Record[]> records = recordsMap.get(Integer.valueOf(type));
			if (records == null) {
				header.setRcode(Rcode.NOTIMP);
				return request;
			}
			answers = records.get(host);
			if (answers != null) {
				domain[0] = host;
			}
			break;
		}
		// AAAA: Convert IPv4 to IPv6
		if (type == Type.AAAA && answers != null) {
			// Do not pollute "aRecords", "aWildcards" or "aDynamics"
			Record[] cloned = new Record[answers.length];
			for (int i = 0; i < answers.length; i ++) {
				Record record = cloned[i] = answers[i];
				if (!(record instanceof ARecord)) {
					continue;
				}
				InetAddress addr = ((ARecord) record).getAddress();
				if (!(addr instanceof Inet4Address)) {
					continue;
				}
				byte[] ip = ((Inet4Address) addr).getAddress();
				try {
					addr = Inet6Address.getByAddress(null,
							new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1,
							ip[0], ip[1], ip[2], ip[3]}, null);
					cloned[i] = new AAAARecord(record.getName(),
							record.getDClass(), record.getTTL(), addr);
				} catch (IOException e) {
					Log.e(e);
				}
			}
			answers = cloned;
		}
		// Get AUTHORITY Records
		Record[] authorities;
		if (type == Type.CAA) {
			authorities = soaRecords.get(host);
		} else {
			authorities = resolveWildcard(nsRecords, host, domain);
		}
		if (answers == null && authorities == null) {
			// Return NXDOMAIN if AUTHORITY not Found
			header.setRcode(Rcode.NXDOMAIN);
			return request;
		}
		// Prepare Response
		boolean rd = header.getFlag(Flags.RD);
		Message response = new Message(header.getID());
		header = response.getHeader();
		header.setRcode(Rcode.NOERROR);
		header.setFlag(Flags.QR);
		header.setFlag(Flags.AA);
		if (rd) {
			header.setFlag(Flags.RD);
		}
		response.addRecord(question, Section.QUESTION);
		HashSet<Name> addNames = new HashSet<>();
		// Set ANSWER
		if (answers != null) {
			for (Record record : answers) {
				response.addRecord(record, Section.ANSWER);
				if (record instanceof CNAMERecord) {
					addNames.add(((CNAMERecord) record).getTarget());
				} else if (record instanceof NSRecord) {
					addNames.add(((NSRecord) record).getTarget());
				} else if (record instanceof MXRecord) {
					addNames.add(((MXRecord) record).getTarget());
				} else if (record instanceof SOARecord) {
					addNames.add(((SOARecord) record).getHost());
				}
			}
		}
		// Set AUTHORITY
		if (authorities != null) {
			for (Record record : authorities) {
				response.addRecord(record, Section.AUTHORITY);
				if (record instanceof NSRecord) {
					addNames.add(((NSRecord) record).getTarget());
				} else if (record instanceof SOARecord) {
					addNames.add(((SOARecord) record).getHost());
				}
			}
		}
		// Set ADDITIONAL
		for (Name addName : addNames) {
			Record[] additionals = aRecords.get(addName.
					toString(true).toLowerCase());
			if (additionals != null) {
				for (Record record : additionals) {
					response.addRecord(record, Section.ADDITIONAL);
				}
			}
		}
		return response;
	}

	private static void forward(SocketAddress addr, byte[] reqData, byte[] respData) {
		for (InetSocketAddress forward : forwards) {
			try (DatagramSocket socket = new DatagramSocket()) {
				socket.setSoTimeout(1000);
				socket.send(new DatagramPacket(reqData, reqData.length, forward));
				byte[] data = new byte[65536];
				DatagramPacket packet = new DatagramPacket(data, data.length);
				try {
					socket.receive(packet);
				} catch (SocketTimeoutException e) {
					continue;
				}
				dataQueue.add(new DataEntry(addr, Bytes.left(data, packet.getLength())));
				return;
			} catch (IOException e) {
				Log.e(e);
			}
		}
		dataQueue.add(new DataEntry(addr, respData));
	}

	private static void response(HttpExchange exchange, int status, byte[] data) {
		try {
			exchange.sendResponseHeaders(status, data == null ? -1 : data.length);
			if (data != null) {
				exchange.getResponseBody().write(data);
			}
		} catch (IOException e) {
			Log.w("Unable to send response to " +
					exchange.getRemoteAddress() + ": " + e.getMessage());
		}
		exchange.close();
	}

	private static void serviceHttp(HttpExchange exchange, String auth, int ttl) {
		if (auth != null) {
			List<String> auths = exchange.getRequestHeaders().get("Authorization");
			if (auths == null || auths.isEmpty() || !auth.equals(auths.get(0))) {
				exchange.getResponseHeaders().add("WWW-Authenticate", "Basic");
				response(exchange, 401, null);
				return;
			}
		}
		URI uri = exchange.getRequestURI();
		String query = uri.getQuery();
		if (query == null) {
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			response(exchange, 200, JSONObject.
					wrap(getDynamicMap()).toString().getBytes());
			return;
		}
		String[] s = query.split("=");
		if (s.length == 0 || s[0].isEmpty()) {
			response(exchange, 400, null);
			return;
		}
		String name = s[0];
		String addr;
		if (s.length == 1 || s[1].isEmpty()) {
			addr = null;
		} else if (s[1].charAt(0) == '_') {
			InetAddress addr_ = exchange.getRemoteAddress().getAddress();
			addr = addr_ instanceof Inet4Address ? addr_.getHostAddress() : null;
		} else {
			addr = s[1];
		}
		// Always Store ?
		try {
			updateRecords(aDynamics, name, addr, ttl, null);
			needWriteBack = true;
			response(exchange, 200, null);
		} catch (IOException e) {
			Log.w("Unable to update record " + name +
					" -> " + addr + ": " + e.getMessage());
			response(exchange, 400, null);
		}
	}

	public static void main(String[] args) {
		if (!service.startup(args)) {
			return;
		}
		System.setProperty("java.util.logging.SimpleFormatter.format",
				"%1$tY-%1$tm-%1$td %1$tk:%1$tM:%1$tS.%1$tL %2$s%n%4$s: %5$s%6$s%n");
		Logger logger = Log.getAndSet(Conf.openLogger("DDNS.", 16777216, 10));
		ScheduledThreadPoolExecutor timer = new ScheduledThreadPoolExecutor(1);

		Properties p = Conf.load("DDNS");
		int port = Numbers.parseInt(p.getProperty("port"), 53);
		String host = p.getProperty("host");
		host = host == null || host.isEmpty() ? "0.0.0.0" : host;
		int dynamicTtl = Numbers.parseInt(p.getProperty("ttl.dynamic"), 10);
		propPeriod = Numbers.parseInt(p.getProperty("prop.period")) * 1000;
		// DoS
		dosPeriod = Numbers.parseInt(p.getProperty("dos.period")) * 1000;
		dosRequests = Numbers.parseInt(p.getProperty("dos.requests"));
		// SOA
		String admin = p.getProperty("soa.admin");
		try {
			soaAdmin = new Name(admin.endsWith(".") ? admin : admin + ".");
		} catch (IOException e) {
			Log.w("Unrecognized host \"" + admin + "\": " + e.getMessage());
			soaAdmin = null;
		}
		// API Client
		HttpPool[] addrApi = {null};
		String addrApiUrl = p.getProperty("addr.url");
		if (addrApiUrl != null) {
			addrApi[0] = new HttpPool(addrApiUrl, dynamicTtl * 2000);
			Map<String, List<String>> addrApiAuth;
			String addrApiAuth_ = p.getProperty("addr.auth");
			if (addrApiAuth_ == null) {
				addrApiAuth = null;
			} else {
				addrApiAuth = Collections.singletonMap("Authorization",
						Collections.singletonList("Basic " + Base64.getEncoder().
						encodeToString(addrApiAuth_.getBytes())));
			}
			timer.scheduleWithFixedDelay(() ->
					updateFromApi(addrApi[0], addrApiAuth, dynamicTtl),
					dynamicTtl, dynamicTtl, TimeUnit.SECONDS);
		}
		// Forward to External DNS
		String forward = p.getProperty("forward");
		if (forward != null && !forward.isEmpty()) {
			for (String s : forward.split("[,;]")) {
				forwards.add(new InetSocketAddress(s, 53));
			}
		}
		// Load Static and Dynamic Records
		loadProp();
		Conf.load("DynamicRecords").forEach((k, v) -> {
			try {
				updateRecords(aDynamics, (String) k,
						(String) v, dynamicTtl, null);
			} catch (IOException e) {
				Log.e(e);
			}
		});
		// HTTP Updating Service
		int httpPort = Numbers.parseInt(p.getProperty("http.port"), 5380);
		String httpHost = p.getProperty("http.host");
		httpHost = httpHost == null || httpHost.isEmpty() ? "0.0.0.0" : httpHost;
		HttpServer httpServer = null;
		if (httpPort > 0) {
			String auth = p.getProperty("http.auth");
			String auth_ = auth == null ? null :
					"Basic " + Base64.getEncoder().encodeToString(auth.getBytes());
			try {
				httpServer = HttpServer.create(new InetSocketAddress(httpPort), 50);
				httpServer.createContext("/", exchange -> serviceHttp(exchange, auth_, dynamicTtl));
				httpServer.start();
				Log.i("DDNS Management Service Started on " + httpHost + ":" + httpPort);
			} catch (IOException e) {
				Log.w("Unable to start HttpServer (" +
						httpHost + ":" + httpPort + "): " + e.getMessage());
			}
		}
		// Metric
		ArrayList<InetSocketAddress> addrs = new ArrayList<>();
		String addresses = p.getProperty("metric.collectors", "");
		for (String s : addresses.split("[,;]")) {
			String[] ss = s.split("[:/]");
			if (ss.length > 1) {
				addrs.add(new InetSocketAddress(ss[0],
						Numbers.parseInt(ss[1], 5514, 0, 65535)));
			}
		}
		MetricClient.startup(addrs.toArray(new InetSocketAddress[0]));
		timer.scheduleAtFixedRate(Runnables.wrap(new ManagementMonitor("ddns.server")),
				0, 5, TimeUnit.SECONDS);

		Runnable writeBack = Runnables.wrap(() -> {
			if (needWriteBack) {
				needWriteBack = false;
				Properties dynamicRedords = new Properties();
				dynamicRedords.putAll(getDynamicMap());
				Conf.store("DynamicRecords", dynamicRedords);
			}
		});
		// Persist Dynamic Records Every Second
		timer.scheduleAtFixedRate(writeBack, 1, 1, TimeUnit.SECONDS);

		try (DatagramSocket socket = new DatagramSocket(new
				InetSocketAddress(host, port))) {
			service.register(socket);
			service.execute(Runnables.wrap(() -> {
				try {
					while (true) {
						DataEntry dataEntry = dataQueue.take();
						try {
							DatagramPacket packet = new DatagramPacket(dataEntry.data,
									dataEntry.data.length, dataEntry.addr);
							socket.send(packet);
							dump(packet, true);
						} catch (IOException e) {
							Log.e(e);
						}
					}
				} catch (InterruptedException e) {
					// Exit Polling
				}
			}));
			Log.i("DDNS Started on UDP " + host + ":" + port);

			while (!Thread.interrupted()) {
				// Load Properties
				if (propPeriod > 0) {
					long now = System.currentTimeMillis();
					if (now > propAccessed + propPeriod) {
						loadProp();
						propAccessed = now;
					}
				}
				// Receive
				byte[] buf = new byte[65536];
				DatagramPacket packet = new DatagramPacket(buf, buf.length);
				// Blocked, or closed by shutdown handler
				socket.receive(packet);
				// DoS Filtering
				SocketAddress remote = packet.getSocketAddress();
				if (blocked(((InetSocketAddress) remote).getAddress().getHostAddress())) {
					continue;
				}
				dump(packet, false);
				byte[] reqData = Bytes.left(buf, packet.getLength());
				Message request;
				try {
					request = new Message(reqData);
				} catch (IOException e) {
					Log.w("Unable to parse " + Bytes.toHexLower(reqData) +
							": " + e.getMessage());
					continue;
				}
				// Call Service in Trunk Thread
				String[] domain = {null};
				Message response = service(request, domain);
				if (response == null) {
					continue;
				}
				int rcode = response.getRcode();
				Record question = request.getQuestion();
				Metric.put("ddns.resolve", 1, "rcode", Rcode.string(rcode),
						"name", "" + domain[0], "type", question == null ?
						"null" : Type.string(question.getType()));
				byte[] respData = response.toWire();
				if (forwards.isEmpty() || rcode < Rcode.NXDOMAIN) {
					// Send
					dataQueue.offer(new DataEntry(remote, respData));
				} else {
					// Call Forward in Branch Thread
					service.execute(Runnables.wrap(() -> forward(remote, reqData, respData)));
				}
			}
		} catch (IOException e) {
			Log.w("Unable to open DatagramSocket (" + port +
					") or receive DatagramPacket: " + e.getMessage());
			service.shutdownNow(); // Interrupt when failed
		} catch (Error | RuntimeException e) {
			Log.e(e);
			service.shutdownNow(); // Interrupt when failed
		}

		if (httpServer != null) {
			httpServer.stop(0);
		}
		MetricClient.shutdown();
		Runnables.shutdown(timer);
		if (addrApi[0] != null) {
			addrApi[0].close();
		}
		writeBack.run();
		Log.i("DDNS Stopped");
		Conf.closeLogger(Log.getAndSet(logger));
		service.shutdown();
	}
}