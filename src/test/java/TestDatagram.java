import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import com.xqbase.util.Bytes;

public class TestDatagram {
	public static void main(String[] args) throws Exception {
		try (DatagramSocket socket = new DatagramSocket()) {
			Message message = new Message();
			Header header = message.getHeader();
			header.setOpcode(Opcode.QUERY);
			header.setID(1);
			header.setRcode(Rcode.NOERROR);
			header.setFlag(Flags.RD);
			message.addRecord(Record.newRecord(new Name("www.xqbase.com."), Type.A, DClass.IN), Section.QUESTION);
			byte[] data = message.toWire();
			DatagramPacket packet = new DatagramPacket(data, data.length, new InetSocketAddress("localhost", 53));
			socket.send(packet);
			data = new byte[65536];
			packet = new DatagramPacket(data, data.length);
			socket.setSoTimeout(2000);
			socket.receive(packet);
			Message response = new Message(Bytes.left(data, packet.getLength()));
			System.out.println(response);
		}
	}
}