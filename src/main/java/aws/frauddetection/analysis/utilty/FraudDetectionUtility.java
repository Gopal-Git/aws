package aws.frauddetection.analysis.utilty;

import static aws.frauddetection.analysis.constants.FraudDectectionConstants.AMOUNT_DEBITED_MSG;
import static aws.frauddetection.analysis.constants.FraudDectectionConstants.RECORD_DELIMITER;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import aws.frauddetection.analysis.model.SessionTransaction;
import aws.frauddetection.analysis.model.UserReport;

/**
 * @author CEP-A41
 *
 */
public class FraudDetectionUtility {

	
	private static Logger log = Logger.getLogger(FraudDetectionUtility.class.getName());
	
	/**
	 * @param sessionLogs
	 * @param report
	 * 
	 * Update report with Different Location
	 */
	public static void analysisForNoOfDifferentLocations(List<String> sessionLogs, Map<String, UserReport> report) {
		String[] tokens = sessionLogs.get(0).split(RECORD_DELIMITER);
		String userId = tokens[3];
		String location = tokens[5];
		
		UserReport userReport = report.get(userId);
		if(userReport==null) {
			populateMapForDifferentLocations(report,userId,location);
		} else {
			Set<String> differentLocations = userReport.getDifferentLocations();
			differentLocations.add(location);
			userReport.setCountOfDifferentLocation(differentLocations.size());
			report.put(userId, userReport);
		}
		
	}
	
	/**
	 * @param report
	 * @param line
	 * 
	 * Update report with Failed Transactions
	 * 
	 */
	public static void analysisForFailedTransaction(Map<String, UserReport> report, String line) {
		//Its failed transaction
		String[] tokens = line.split(RECORD_DELIMITER);
		String userId = tokens[2];
		String location = tokens[4];
		if(report.get(userId)==null) {
			populateMapForFailedTransaction(report, userId,location);
		} else {
			// get existing object from 
			UserReport userReport  = report.get(userId);
			int countOfFailedTransaction = userReport.getCountOfFailedTransaction();
			int updatedCountOfFailedTransaction = countOfFailedTransaction+1;
			
			// update locations
			Set<String> differentLocations = userReport.getDifferentLocations();
			differentLocations.add(location);
			int updatedCountOfDifferentLocation = differentLocations.size();
			
			userReport.setCountOfDifferentLocation(updatedCountOfDifferentLocation);
			userReport.setDifferentLocations(differentLocations);
			userReport.setCountOfFailedTransaction(updatedCountOfFailedTransaction);
			report.put(userId, userReport);
		}
	}
	
	/**
	 * @param sessionLogs
	 * @param report
	 * 
	 * Update report with Session Transaction
	 * 
	 */
	public static void analysisForNoOfTransactionInSession(List<String> sessionLogs, Map<String, UserReport> report) {
		String[] tokens = sessionLogs.get(0).split(RECORD_DELIMITER);
		String sessionId = tokens[2];
		String userId = tokens[3];
		UserReport userReport = report.get(userId);
		Long count = sessionLogs.stream().filter(log->log.contains(AMOUNT_DEBITED_MSG)).count();
		if(userReport==null) {
			populateMapForSessionTransaction(report, userId,sessionId,count);
		} else {
			List<SessionTransaction> listSessionTransaction = userReport.getSessionTransaction();
			SessionTransaction sessionTransaction = new SessionTransaction();
			sessionTransaction.setCountOfTransactionInSession(count.intValue());
			sessionTransaction.setSessionId(sessionId);
			listSessionTransaction.add(sessionTransaction);
			userReport.setSessionTransaction(listSessionTransaction);
			report.put(userId, userReport);
			
		}
	}

	
	
	/**
	 * @param report
	 * @param userId
	 * @param location
	 * 
	 * Initiate the User Report with Different Location
	 * 
	 */
	private static void populateMapForDifferentLocations(Map<String, UserReport> report, String userId,String location) {
		UserReport userReport = new UserReport();
		int countOfFailedTransaction=0;
		Set<String> differentLocations = new HashSet<>();
		differentLocations.add(location);
		int countOfDifferentLocation= differentLocations.size();
		List<SessionTransaction> listofSessionTransaction = new ArrayList<>();
		
		userReport.setSessionTransaction(listofSessionTransaction);
		userReport.setUserId(userId);
		userReport.setCountOfDifferentLocation(countOfDifferentLocation);
		userReport.setDifferentLocations(differentLocations);
		userReport.setCountOfFailedTransaction(countOfFailedTransaction);
		report.put(userId, userReport);
	}
	
	
	/**
	 * @param report
	 * @param userId
	 * @param location
	 * 
	 * Initiate the User Report with Failed Transactions
	 */
	private static void populateMapForFailedTransaction(Map<String, UserReport> report, String userId,String location) {
		//populate UserReport for failed transaction
		UserReport userReport = new UserReport();
		int countOfFailedTransaction=1;//this is first failed Transaction;
		int countOfDifferentLocation= 1; //this is first failed Transaction
		Set<String> differentLocations = new HashSet<>();
		differentLocations.add(location);
		List<SessionTransaction> listofSessionTransaction = new ArrayList<>();
		
		userReport.setSessionTransaction(listofSessionTransaction);
		userReport.setUserId(userId);
		userReport.setCountOfDifferentLocation(countOfDifferentLocation);
		userReport.setDifferentLocations(differentLocations);
		userReport.setCountOfFailedTransaction(countOfFailedTransaction);
		report.put(userId, userReport);
	}
	
	/**
	 * @param report
	 * @param userId
	 * @param sessionId
	 * @param count
	 * 
	 * Initiate the User Report with Session Transactions
	 * 
	 */
	private static void populateMapForSessionTransaction(Map<String, UserReport> report, String userId, String sessionId, Long count) {
		UserReport userReport = new UserReport();
		int countOfFailedTransaction=0;
		int countOfDifferentLocation= 0;
		Set<String> differentLocations = new HashSet<>();
		
		
		List<SessionTransaction> listofSessionTransaction = new ArrayList<>();
		SessionTransaction sessionTransaction = new SessionTransaction();
		sessionTransaction.setCountOfTransactionInSession(count.intValue());
		sessionTransaction.setSessionId(sessionId);
		listofSessionTransaction.add(sessionTransaction);
		
		userReport.setSessionTransaction(listofSessionTransaction);
		userReport.setUserId(userId);
		userReport.setCountOfDifferentLocation(countOfDifferentLocation);
		userReport.setDifferentLocations(differentLocations);
		userReport.setCountOfFailedTransaction(countOfFailedTransaction);
		report.put(userId, userReport);
	}
	

	
	/**
	 * @param report
	 * 
	 * Convert to JSON and push data to S2 bucket
	 * 
	 */
	public static void convertToJsonAndPushReportsToS3(Map<String, UserReport> report) {
		ObjectMapper mapper = new ObjectMapper();
		try {
			String jsonString = mapper.writeValueAsString(report);
			log.info(jsonString);
			//TODO Push report to S3
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			log.error("Unable to convert to JSON, ",e);
		}  catch (Exception e) {
			log.error("Exception occured while converting to json",e);
		}
	}
	
	
	/**
	 * @param report
	 * 
	 * Send notification when fraud is detected
	 * 
	 */
	public static void sendNotification(Map<String, UserReport> report) {
		report.entrySet().forEach(entry->{
			UserReport userReport = entry.getValue();
			if(userReport.getCountOfDifferentLocation()>2) {
				//TODO send notification for multiple location access fraud alert
			} 
			if(userReport.getCountOfFailedTransaction()>2) {
				//TODO notification for multiple failed transaction fraud alert
			}
		
			userReport.getSessionTransaction().forEach(trans->{
				if(trans.getCountOfTransactionInSession()>2) {
					//TODO send notification for multiple transaction in a session
				}
			});
		});
	}
}
