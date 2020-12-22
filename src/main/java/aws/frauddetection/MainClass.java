package aws.frauddetection;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.log4j.Logger;

public class MainClass {
	static {
		SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy-hh-mm-ss");
		System.setProperty("currenttime", dateFormat.format(new Date()));
	}
	static Logger log = Logger.getLogger(MainClass.class.getName());
	public static void main(String args[]) {
		log.info("2020-11-26 00:00:07 LoginService 2719322321342  UID101 Login-Successful 172.65.88.54");
		log.info("2020-11-26 00:00:28 TransactionService - 2719322321342 UID101 Balance Inquiry  172.65.88.54");
		log.info("2020-11-26 00:00:32 TransactionService - 2719322321342 UID101 Balance Inquiry  172.65.88.54");
		log.info("2020-11-26 00:00:55 TransactionService - 2719322321342 UID101 Amount Debited  172.65.88.54");
		log.info("2020-11-26 00:01:21 TransactionService - 2719322321342 UID101 Amount Credited  172.65.88.54");
		log.info("2020-11-26 00:01:30 TransactionService - 2719322321342 UID101 Amount Debited  172.65.88.54");
		log.info("2020-11-26 00:02:07 LoginService 2719322321342  UID101 Logout-Successful 172.65.88.54");

		log.info("2020-11-26 00:05:07 LoginService 23343J43334  UID101 Login-Successful 172.60.32.66");
		log.info("2020-11-26 00:06:28 TransactionService - 23343J43334 UID101 Balance Inquiry 172.60.32.66");
		log.info("2020-11-26 00:06:32 TransactionService - 23343J43334 UID101 Balance Inquiry  172.60.32.66");
		log.info("2020-11-26 00:06:55 TransactionService - 23343J43334 UID101 Amount Debited  172.60.32.66");
		log.info("2020-11-26 00:07:21 TransactionService - 23343J43334 UID101 Amount Debited   172.60.32.66");
		log.info("2020-11-26 00:08:30 TransactionService - 23343J43334 UID101 Amount Debited  172.60.32.66");
		log.info("2020-11-26 00:08:07 LoginService 23343J43334  UID101 Logout-Successful 172.60.32.66");

		log.info("2020-11-26 00:05:07 LoginService 23343J23443  UID101 Login-Successful 172.69.67.88");
		log.info("2020-11-26 00:06:28 TransactionService - 23343J23443 UID101 Balance Inquiry 172.69.67.88");
		log.info("2020-11-26 00:06:32 TransactionService - 23343J23443 UID101 Balance Inquiry  172.69.67.88");
		log.info("2020-11-26 00:06:55 TransactionService - 23343J23443 UID101 Amount Credited  172.69.67.88");
		log.info("2020-11-26 00:07:21 TransactionService - 23343J23443 UID101 Amount Credited   172.69.67.88");
		log.info("2020-11-26 00:08:30 TransactionService - 23343J23443 UID101 Amount Credited  172.69.67.88");
		log.info("2020-11-26 00:08:07 LoginService 23343J23443  UID101 Logout-Successful 172.69.67.88");
		log.info("2020-11-26 00:05:07 LoginService UID101 Login-Attempted-Failed 192.168.30.01");
		log.info("2020-11-26 00:05:07 LoginService UID101 Login-Attempted-Failed 192.102.06.78");
	}
}
