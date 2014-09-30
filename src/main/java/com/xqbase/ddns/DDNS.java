package com.xqbase.ddns;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
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
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import com.xqbase.metric.aggregator.ManagementMonitor;
import com.xqbase.metric.aggregator.Metric;
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
	private static ConcurrentHashMap<String, Record[]>
			dynamicARecords = new ConcurrentHashMap<>(),
			dynamicAAAARecords = new ConcurrentHashMap<>();
	private static HashMap<String, Record[]>
			staticARecords = new HashMap<>(),
			staticAAAARecords = new HashMap<>(),
			nsRecords = new HashMap<>(),
			mxRecords = new HashMap<>();
	private static ArrayList<String> wildcards = new ArrayList<>();
	private static ArrayList<InetSocketAddress> dnss = new ArrayList<>();
	private static Properties dynamicRecords;

	private static void updateRecords(Map<String, Record[]> aRecords,
			Map<String, Record[]> aaaaRecords, String host, String value,
			int ttl, boolean wildcard) throws IOException {
		Name origin = wildcard ? new Name("localhost.") :
				new Name((host.endsWith(".") ? host : host + ".").replace('_', '-'));
		ArrayList<Record> records = new ArrayList<>(), records6 = new ArrayList<>();
		for (String s : value.split("[,;]")) {
			if (s.matches(".*[A-Z|a-z].*")) {
				CNAMERecord record = new CNAMERecord(origin, DClass.IN, ttl,
						new Name(s.endsWith(".") ? s : s + "."));
				records.add(record);
				records6.add(record);
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
			records.add(new ARecord(origin, DClass.IN,
					ttl, InetAddress.getByAddress(ip)));
			byte[] ip6 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, ip[0], ip[1], ip[2], ip[3]};
			records6.add(new AAAARecord(origin, DClass.IN,
					ttl, Inet6Address.getByAddress(null, ip6, null)));
		}
		if (!records.isEmpty()) {
			aRecords.put(host, records.toArray(new Record[0]));
		}
		if (!records6.isEmpty()) {
			aaaaRecords.put(host, records6.toArray(new Record[0]));
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
					updateRecords(dynamicARecords, dynamicAAAARecords,
							host, addr, ttl, false);
				}
			}
		} catch (IOException | JSONException e) {
			Log.e(e);
		}
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

	private static Message getError(Header header, int rcode, Record question) {
		Message response = new Message();
		response.setHeader(header);
		header.setRcode(rcode);
		header.setFlag(Flags.QR);
		response.addRecord(question, Section.QUESTION);
		return response;
	}

	private static Record[] resolve(String host, Map<String, Record[]> staticRecords,
			Map<String, Record[]> dynamicRecords_) {
		Record[] records = staticRecords.get(host);
		if (records != null) {
			return records;
		}
		for (String wildcard : wildcards) {
			if (!host.endsWith(wildcard)) {
				continue;
			}
			records = staticRecords.get(wildcard);
			if (records == null) {
				continue;
			}
			for (int i = 0; i < records.length; i ++) {
				Record record = records[i];
				Name name;
				try {
					name = new Name(host.endsWith(".") ? host : host + ".");
				} catch (IOException e) {
					Log.w(e.getMessage());
					continue;
				}
				int dclass = record.getDClass();
				long ttl = record.getTTL();
				if (record instanceof ARecord) {
					records[i] = new ARecord(name, dclass, ttl,
							((ARecord) record).getAddress());
				} else if (record instanceof AAAARecord) {
					records[i] = new AAAARecord(name, dclass, ttl,
							((AAAARecord) record).getAddress());
				}
			}
			return records;
		}
		return dynamicRecords_.get(host);
	}

	private static Message service(Message request) {
		Header reqHeader = request.getHeader();
		if (reqHeader.getFlag(Flags.QR)) {
			return null;
		}
		Record question = request.getQuestion();
		if (reqHeader.getRcode() != Rcode.NOERROR) {
			return getError(reqHeader, Rcode.FORMERR, question);
		}
		if (reqHeader.getOpcode() != Opcode.QUERY) {
			return getError(reqHeader, Rcode.NOTIMP, question);
		}
		
		String host = question.getName().toString(true).toLowerCase();
		Record[] records;
		int type = question.getType();
		switch (type) {
		case Type.A:
		case Type.ANY:
			records = resolve(host, staticARecords, dynamicARecords);
			break;
		case Type.NS:
			records = nsRecords.get(host);
			break;
		case Type.MX:
			records = mxRecords.get(host);
			break;
		case Type.AAAA:
			records = resolve(host, staticAAAARecords, dynamicAAAARecords);
			break;
		default:
			return getError(reqHeader, Rcode.NOTIMP, question);
		}
		if (records == null) {
			return getError(reqHeader, Rcode.NXDOMAIN, question);
		}
		Message response = new Message(reqHeader.getID());
		Header respHeader = response.getHeader();
		respHeader.setRcode(Rcode.NOERROR);
		respHeader.setFlag(Flags.QR);
		respHeader.setFlag(Flags.AA);
		if (reqHeader.getFlag(Flags.RD)) {
			respHeader.setFlag(Flags.RD);
		}
		response.addRecord(question, Section.QUESTION);
		for (Record record : records) {
			response.addRecord(record, Section.ANSWER);
		}
/*
		if (type != Type.NS) {
			for (Record[] records_ : nsRecords.values()) {
				for (Record record : records_) {
					response.addRecord(record, Section.AUTHORITY);
				}
			}
		}
*/
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
					new JSONObject(dynamicRecords).toString().getBytes());
			return;
		}
		String[] s = query.split("=");
		if (s.length != 2) {
			response(exchange, 400, null);
			return;
		}
		dynamicRecords.setProperty(s[0], s[1]);
		Conf.store("DynamicRecords", dynamicRecords);
		try {
			updateRecords(dynamicARecords, dynamicAAAARecords, s[0], s[1], ttl, false);
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
		int mxPriority = Numbers.parseInt(p.getProperty("priority.mx"), 10);
		int staticTtl = Numbers.parseInt(p.getProperty("ttl.static"), 3600);
		final int dynamicTtl = Numbers.parseInt(p.getProperty("ttl.dynamic"), 10);
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
		// HTTP Updating Service
		int httpPort = Numbers.parseInt(p.getProperty("http.port"), 5380);
		HttpServer httpServer = null;
		if (httpPort > 0) {
			String auth = p.getProperty("http.auth");
			final String auth_ = auth == null ? null :
					"Basic " + Base64.encode(auth.getBytes());
			dynamicRecords = Conf.load("DynamicRecords");
			try {
				for (Map.Entry<?, ?> entry : dynamicRecords.entrySet()) {
					updateRecords(dynamicARecords, dynamicAAAARecords, (String)
							entry.getKey(), (String) entry.getValue(), dynamicTtl, false);
				}
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
		Metric.startup(addrs.toArray(new InetSocketAddress[0]));
		Executors.schedule(new ManagementMonitor("ddns.server"), 0, 5000);

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
						nsRecords.put(host, records.toArray(new Record[0]));
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
						mxRecords.put(host, records.toArray(new Record[0]));
					}
					continue;
				}
				if (!key.startsWith("a_")) {
					continue;
				}
				String host = key.substring(2);
				if (host.isEmpty()) {
					continue;
				}
				boolean wildcard = false;
				if (host.charAt(0) == '*') {
					wildcard = true;
					host = host.substring(1);
					wildcards.add(host);
				}
				updateRecords(staticARecords, staticAAAARecords, host, value, staticTtl, wildcard);
			} catch (IOException e) {
				Log.e(e);
			}
		}
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
				// Receive
				byte[] buf = new byte[65536];
				final DatagramPacket packet = new DatagramPacket(buf, buf.length);
				// Blocked, or closed by shutdown handler
				socket.receive(packet);
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
				Message response = service(request);
				if (response == null) {
					continue;
				}
				int rcode = response.getRcode();
				Record question = request.getQuestion();
				String name = "null";
				if (rcode == Rcode.NOERROR && question != null) {
					Name name_ = question.getName();
					if (name_ != null) {
						int labels = name_.labels();
						if (labels >= 3 && name_.getLabelString(labels - 1).isEmpty()) {
							name = name_.getLabelString(labels - 3).toLowerCase() +
									"." + name_.getLabelString(labels - 2).toLowerCase();
						} else if (labels >= 2) {
							name = name_.getLabelString(labels - 2).toLowerCase() +
									"." + name_.getLabelString(labels - 1).toLowerCase();
						}
					}
				}
				Metric.put("ddns.resolve", 1, "rcode", Rcode.string(rcode), "name", name,
						"type", question == null ? "null" : Type.string(question.getType()));
				final byte[] respData = response.toWire();
				if (dnss.isEmpty() || rcode < Rcode.NXDOMAIN) {
					// Send
					dataQueue.offer(new DataEntry(packet.getSocketAddress(), respData));
				} else {
					// Call DNS Service in Branch Thread
					Executors.execute(new Runnable() {
						@Override
						public void run() {
							serviceDns(packet.getSocketAddress(), reqData, respData);
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
		Metric.shutdown();
		Executors.shutdown();
		Log.i("DDNS Stopped");
		Conf.closeLogger(Log.getAndSet(logger));
	}
}