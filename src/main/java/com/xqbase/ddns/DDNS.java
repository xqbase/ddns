package com.xqbase.ddns;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

import org.json.JSONException;
import org.json.JSONObject;
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
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import com.xqbase.metric.client.ManagementMonitor;
import com.xqbase.metric.client.MetricClient;
import com.xqbase.metric.common.Metric;
import com.xqbase.util.ByteArrayQueue;
import com.xqbase.util.Bytes;
import com.xqbase.util.Conf;
import com.xqbase.util.Executors;
import com.xqbase.util.Log;
import com.xqbase.util.Numbers;
import com.xqbase.util.ShutdownHook;
import com.xqbase.util.Time;
import com.xqbase.util.http.HttpPool;

class DataEntry {
	SocketAddress addr;
	byte[] data;

	DataEntry(SocketAddress addr, byte[] data) {
		this.addr = addr;
		this.data = data;
	}
}

public class DDNS {
	private static final Record[] EMPTY_RECORDS = new Record[0];
	private static ConcurrentHashMap<String, Record[]>
			dynamicRecords = new ConcurrentHashMap<>();
	private static HashMap<String, Record[]>
			aRecords = new HashMap<>(), aWildcards = new HashMap<>(),
			nsRecords = new HashMap<>(), mxRecords = new HashMap<>();
	private static ArrayList<InetSocketAddress> dnss = new ArrayList<>();
	private static Properties dynamicProperties;
	private static HashMap<String, Integer> countMap = new HashMap<>();
	private static long propAccessed = 0, dosAccessed = 0;
	private static int propPeriod, dosPeriod, dosRequests;

	private static void updateRecords(Map<String, Record[]> records,
			String host, String value, int ttl) throws IOException {
		Name origin = new Name((host.endsWith(".") ? host : host + ".").replace('_', '-'));
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
		}
		if (!recordList.isEmpty()) {
			records.put(host, recordList.toArray(EMPTY_RECORDS));
		}
	}

	static void updateDynamicRecords(HttpPool addrApi, int ttl) {
		ByteArrayQueue body = new ByteArrayQueue();
		try {
			if (addrApi.get("", null, body, null) >= 400) {
				Log.w(body.toString());
				return;
			}
		} catch (IOException e) {
			Log.e(e);
			return;
		}
		try {
			JSONObject map = new JSONObject(body.toString());
			Iterator<?> it = map.keys();
			while (it.hasNext()) {
				String host = (String) it.next();
				String addr = map.optString(host);
				if (addr != null) {
					updateRecords(dynamicRecords, host, addr, ttl);
				}
			}
		} catch (IOException | JSONException e) {
			Log.e(e);
		}
	}

	private static void loadProp() {
		aRecords.clear();
		aWildcards.clear();
		nsRecords.clear();
		mxRecords.clear();
		Properties p = Conf.load("DDNS");
		int mxPriority = Numbers.parseInt(p.getProperty("priority.mx"), 10);
		int staticTtl = Numbers.parseInt(p.getProperty("ttl.static"), 3600);
		for (Map.Entry<?, ?> entry : p.entrySet()) {
			String key = (String) entry.getKey();
			String value = (String) entry.getValue();
			try {
				if (key.startsWith("ns_")) {
					String host = key.substring(3);
					Name origin = new Name(host.endsWith(".") ? host : host + ".");
					ArrayList<Record> records = new ArrayList<>();
					for (String target : value.split("[,;]")) {
						records.add(new NSRecord(origin, DClass.IN, staticTtl,
								new Name(target.endsWith(".") ? target : target + ".")));
					}
					if (!records.isEmpty()) {
						nsRecords.put(host, records.toArray(EMPTY_RECORDS));
					}
					continue;
				}
				if (key.startsWith("mx_")) {
					String host = key.substring(3);
					Name origin = new Name(host.endsWith(".") ? host : host + ".");
					ArrayList<Record> records = new ArrayList<>();
					for (String target : value.split("[,;]")) {
						records.add(new MXRecord(origin, DClass.IN, staticTtl, mxPriority,
								new Name(target.endsWith(".") ? target : target + ".")));
					}
					if (!records.isEmpty()) {
						mxRecords.put(host, records.toArray(EMPTY_RECORDS));
					}
					continue;
				}
				if (!key.startsWith("a_")) {
					continue;
				}
				String host = key.substring(2);
				if (host.startsWith("*.")) {
					updateRecords(aWildcards, host.substring(2), value, staticTtl);
				} else {
					updateRecords(aRecords, host, value, staticTtl);
				}
			} catch (IOException e) {
				Log.e(e);
			}
		}
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

	/**
	 * @param packet
	 * @param send
	 */
	static void dump(DatagramPacket packet, boolean send) {
/*
		StringWriter sw = new StringWriter();
		PrintWriter out = new PrintWriter(sw);
		out.println((send ? "Sent to " : "Received from ") +
				packet.getAddress().getHostAddress());
		Bytes.dump(out, packet.getData(), packet.getOffset(), packet.getLength());
		Log.d(sw.toString());
*/
	}

	private static Record[] resolveWildcard(Map<String, Record[]>
			wildcards, String[] domain) {
		String host = domain[0];
		Record[] records = wildcards.get(host);
		while (records == null) {
			int dot = host.indexOf('.');
			if (dot < 0) {
				break;
			}
			host = host.substring(dot + 1);
			if (host.isEmpty()) {
				break;
			}
			records = wildcards.get(host);
			domain[0] = host;
		}
		return records;
	}

	private static Message service(Message request, String[] domain) {
		// Check Request Validity
		Header header = request.getHeader();
		if (header.getFlag(Flags.QR)) {
			return null;
		}
		header.setFlag(Flags.QR);
		Record question = request.getQuestion();
		if (header.getRcode() != Rcode.NOERROR) {
			header.setRcode(Rcode.FORMERR);
			return request;
		}
		if (header.getOpcode() != Opcode.QUERY) {
			header.setRcode(Rcode.NOTIMP);
			return request;
		}
		// Get ANSWER Records
		String host = question.getName().toString(true).toLowerCase();
		Record[] answers;
		switch (question.getType()) {
		case Type.A:
		case Type.CNAME:
		case Type.ANY:
			answers = aRecords.get(host);
			if (answers != null) {
				break;
			}
			answers = resolveWildcard(aWildcards, new String[] {host});
			if (answers == null) {
				answers = dynamicRecords.get(host);
				break;
			}
			Name name;
			try {
				name = new Name(host.endsWith(".") ? host : host + ".");
			} catch (IOException e) {
				Log.w(e.getMessage());
				break;
			}
			// Do not pollute "wildcards"
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
		case Type.NS:
			answers = nsRecords.get(host);
			break;
		case Type.MX:
			answers = mxRecords.get(host);
			break;
		default:
			answers = null;
		}
		// Get AUTHORITY Records
		domain[0] = host;
		Record[] authorities = resolveWildcard(nsRecords, domain);
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
				}
			}
		}
		// Set AUTHORITY
		if (authorities != null) {
			for (Record record : authorities) {
				response.addRecord(record, Section.AUTHORITY);
				addNames.add(((NSRecord) record).getTarget());
			}
		}
		// Set ADDITIONAL
		for (Name name : addNames) {
			Record[] additionals = aRecords.get(name.
					toString(true).toLowerCase());
			if (additionals != null) {
				for (Record record : additionals) {
					response.addRecord(record, Section.ADDITIONAL);
				}
			}
		}
		return response;
	}

	static LinkedBlockingQueue<DataEntry> dataQueue = new LinkedBlockingQueue<>();

	static void serviceDns(SocketAddress addr, byte[] reqData, byte[] respData) {
		for (InetSocketAddress dns : dnss) {
			try (DatagramSocket socket = new DatagramSocket()) {
				socket.setSoTimeout(1000);
				socket.send(new DatagramPacket(reqData, reqData.length, dns));
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
			Log.w(e.getMessage());
		}
		exchange.close();
	}

	static void serviceHttp(HttpExchange exchange, String auth, int ttl) {
		if (auth != null) {
			List<String> auths = exchange.getRequestHeaders().get("Authorization");
			if (auths == null || auths.isEmpty() || !auth.equals(auths.get(0))) {
				exchange.getResponseHeaders().add("WWW-Authenticate",
						"Basic realm=\"Dynamic DNS\"");
				response(exchange, 401, null);
				return;
			}
		}
		URI uri = exchange.getRequestURI();
		String query = uri.getQuery();
		if (query == null) {
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			response(exchange, 200,
					new JSONObject(dynamicProperties).toString().getBytes());
			return;
		}
		String[] s = query.split("=");
		if (s.length != 2) {
			response(exchange, 400, null);
			return;
		}
		dynamicProperties.setProperty(s[0], s[1]);
		Conf.store("DynamicRecords", dynamicProperties);
		try {
			updateRecords(dynamicRecords, s[0], s[1], ttl);
			response(exchange, 200, null);
		} catch (IOException e) {
			Log.w(e.getMessage());
			response(exchange, 400, null);
		}
	}

	static ShutdownHook hook = new ShutdownHook();

	public static void main(String[] args) {
		if (hook.isShutdown(args)) {
			return;
		}
		Logger logger = Log.getAndSet(Conf.openLogger("DDNS.", 16777216, 10));

		Properties p = Conf.load("DDNS");
		int port = Numbers.parseInt(p.getProperty("port"), 53);
		final int dynamicTtl = Numbers.parseInt(p.getProperty("ttl.dynamic"), 10);
		propPeriod = Numbers.parseInt(p.getProperty("prop.period")) * 1000;
		// DoS
		dosPeriod = Numbers.parseInt(p.getProperty("dos.period")) * 1000;
		dosRequests = Numbers.parseInt(p.getProperty("dos.requests"));
		// API Client
		String addrApiUrl = p.getProperty("api.addr");
		if (addrApiUrl != null) {
			final HttpPool addrApi = new HttpPool(addrApiUrl, dynamicTtl * 2000);
			Executors.execute(new Runnable() {
				@Override
				public void run() {
					long lastAccessed = 0;
					while (!hook.isInterrupted()) {
						long now = System.currentTimeMillis();
						if (now - lastAccessed > dynamicTtl * 1000) {
							lastAccessed = now;
							updateDynamicRecords(addrApi, dynamicTtl);
						}
						Time.sleep(16);
					}
					addrApi.close();
				}
			});
		}
		// External DNS
		String dns = p.getProperty("dns");
		if (dns != null && !dns.isEmpty()) {
			for (String s : dns.split("[,;]")) {
				dnss.add(new InetSocketAddress(s, 53));
			}
		}
		// Load Static and Dynamic Records
		loadProp();
		dynamicProperties = Conf.load("DynamicRecords");
		try {
			for (Map.Entry<?, ?> entry : dynamicProperties.entrySet()) {
				updateRecords(dynamicRecords, (String) entry.getKey(),
						(String) entry.getValue(), dynamicTtl);
			}
		} catch (IOException e) {
			Log.e(e);
		}
		// HTTP Updating Service
		int httpPort = Numbers.parseInt(p.getProperty("http.port"), 5380);
		HttpServer httpServer = null;
		if (httpPort > 0) {
			String auth = p.getProperty("http.auth");
			final String auth_ = auth == null ? null :
					"Basic " + Base64.encode(auth.getBytes());
			try {
				httpServer = HttpServer.create(new InetSocketAddress(httpPort), 50);
				httpServer.createContext("/", new HttpHandler() {
					@Override
					public void handle(HttpExchange exchange) {
						serviceHttp(exchange, auth_, dynamicTtl);
					}
				});
				httpServer.start();
			} catch (IOException e) {
				Log.e(e);
			}
		}
		// Metric
		ArrayList<InetSocketAddress> addrs = new ArrayList<>();
		String addresses = p.getProperty("metric.collectors");
		if (addresses != null) {
			String[] s = addresses.split("[,;]");
			for (int i = 0; i < s.length; i ++) {
				String[] ss = s[i].split("[:/]");
				if (ss.length >= 2) {
					addrs.add(new InetSocketAddress(ss[0],
							Numbers.parseInt(ss[1], 5514)));
				}
			}
		}
		MetricClient.startup(addrs.toArray(new InetSocketAddress[0]));
		Executors.schedule(new ManagementMonitor("ddns.server"), 0, 5000);

		Log.i("DDNS Started");

		// For Debug on localhost (192.168.0.1:53 is bound by Microsoft Loopback Adapter)
		// try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress("127.0.0.1", port))) {
		try (DatagramSocket socket = new DatagramSocket(port)) {
			hook.register(socket);
			hook.execute(new Runnable() {
				@Override
				public void run() {
					try {
						while (true) {
							DataEntry dataEntry = dataQueue.take();
							try {
								DatagramPacket packet = new DatagramPacket(dataEntry.data,
										dataEntry.data.length, dataEntry.addr);
								socket.send(packet);
								dump(packet, true);
							} catch (IOException e) {
								Log.w(e);
							}
						}
					} catch (InterruptedException e) {
						// Exit Polling
					}
				}
			});
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
				final SocketAddress remote = packet.getSocketAddress();
				if (blocked(((InetSocketAddress) remote).getAddress().getHostAddress())) {
					continue;
				}
				dump(packet, false);
				final byte[] reqData = Bytes.left(buf, packet.getLength());
				Message request;
				try {
					request = new Message(reqData);
				} catch (IOException e) {
					Log.w(e.getMessage());
					continue;
				}
				// Call Service in Trunk Thread
				String[] domain = {"null"};
				Message response = service(request, domain);
				if (response == null) {
					continue;
				}
				int rcode = response.getRcode();
				Record question = request.getQuestion();
				Metric.put("ddns.resolve", 1, "rcode", Rcode.string(rcode), "name", domain[0],
						"type", question == null ? "null" : Type.string(question.getType()));
				final byte[] respData = response.toWire();
				if (dnss.isEmpty() || rcode < Rcode.NXDOMAIN) {
					// Send
					dataQueue.offer(new DataEntry(remote, respData));
				} else {
					// Call DNS Service in Branch Thread
					Executors.execute(new Runnable() {
						@Override
						public void run() {
							serviceDns(remote, reqData, respData);
						}
					});
				}
			}
		} catch (IOException e) {
			Log.w(e.getMessage());
			hook.handle(null); // Interrupt when failed
		} catch (Error | RuntimeException e) {
			Log.e(e);
			hook.handle(null); // Interrupt when failed
		}

		if (httpServer != null) {
			httpServer.stop(0);
		}
		MetricClient.shutdown();
		Executors.shutdown();
		Log.i("DDNS Stopped");
		Conf.closeLogger(Log.getAndSet(logger));
	}
}