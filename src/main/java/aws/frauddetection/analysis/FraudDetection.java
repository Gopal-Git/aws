package aws.frauddetection.analysis;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;

import aws.frauddetection.analysis.model.UserReport;

public class FraudDetection {
	private static Logger log = Logger.getLogger(FraudDetection.class.getName());

	public static void main(String[] args) {
		Map<String, UserReport> report = new HashMap<>();
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(
					new FileReader("F:\\IMPETUS\\AWS_impetus\\input\\FakerLogs_2020_12_21_17_39.txt"));
			String line = reader.readLine();
			while (line != null) {
				System.out.println(line);
				if(line.contains("Login-Attempted-Failed")) {
					analysisForFailedTransaction(report, line);
					System.out.println("failed transaction");
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
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}

	private static void analysisForFailedTransaction(Map<String, UserReport> report, String line) {
		//Its failed transaction
		String[] tokens = line.split("  ");
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

	private static void populateMapForFailedTransaction(Map<String, UserReport> report, String userId,String location) {
		//populate UserReport for failed transaction
		UserReport userReport = new UserReport();
		int countOfFailedTransaction=1;//this is first failed Transaction;
		int countOfDifferentLocation= 1; //this is first failed Transaction
		Set<String> differentLocations = new HashSet<>();
		differentLocations.add(location);
		
		userReport.setUserId(userId);
		userReport.setCountOfDifferentLocation(countOfDifferentLocation);
		userReport.setDifferentLocations(differentLocations);
		userReport.setCountOfFailedTransaction(countOfFailedTransaction);
		report.put(userId, userReport);
	}
}
