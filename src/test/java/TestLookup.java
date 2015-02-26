import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;

public class TestLookup {
	public static void main(String[] args) throws Exception {
		Lookup lookup = new Lookup("www.xqbase.com");
		lookup.setResolver(new SimpleResolver("localhost"));
		lookup.run();
		for (Record record : lookup.getAnswers()) {
			System.out.println(record);
		}
	}
}