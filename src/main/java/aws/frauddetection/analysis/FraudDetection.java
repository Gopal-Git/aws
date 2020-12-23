package aws.frauddetection.analysis;

import static aws.frauddetection.analysis.constants.FraudDectectionConstants.LOGOUT_SERVICE_MSG;
import static aws.frauddetection.analysis.constants.FraudDectectionConstants.LOGOUT_SUCCESS_MSG;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import aws.frauddetection.analysis.model.UserReport;
import aws.frauddetection.analysis.utilty.FraudDetectionUtility;
/**
 * @author CEP-A41 
 * 
 * Analyzes logs and detects fraud. The report is pushed to S3 bucket and notification is sent to the user
 * 
 *
 */
public class FraudDetection {

	private static Logger log = Logger.getLogger(FraudDetection.class.getName());

	public static void main(String[] args) {
		Map<String, UserReport> report = new HashMap<>();
		BufferedReader reader = null;
		List<String> sessionLogs = new ArrayList<>();
		try {
			//TODO Read from S3 instead
			reader = new BufferedReader(new FileReader("F:\\IMPETUS\\AWS_impetus\\input\\FakerLogs_2020_12_21_17_39.txt"));
			String line = reader.readLine();
			while (line != null) {
				if(line.contains("Login-Attempted-Failed")) {
					FraudDetectionUtility.analysisForFailedTransaction(report, line);
					log.info("There is a failed transaction");
				} else {
					//Perform other analysis
						sessionLogs.add(line);
					if (line.contains(LOGOUT_SERVICE_MSG) && line.contains(LOGOUT_SUCCESS_MSG)) {
						//Perform analysis on session data captured 
						FraudDetectionUtility.analysisForNoOfTransactionInSession(sessionLogs,report);
						FraudDetectionUtility.analysisForNoOfDifferentLocations(sessionLogs,report);
						sessionLogs.clear();
					}
				}
				line = reader.readLine();
			}
		} catch (Exception exception) {
			log.error("Unable to generate report ", exception);
		} finally {
			if(reader!=null) {
				try {
					reader.close();
				} catch (IOException e) {
					log.error("Unable to close connectin",e);
				}
			}
		}
		FraudDetectionUtility.convertToJsonAndPushReportsToS3(report);
		FraudDetectionUtility.sendNotification(report);
	}

}
