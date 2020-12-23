package aws.frauddetection.analysis.model;

import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * @author CEP-A41
 *
 */
public class UserReport {

	String userId;
	List<SessionTransaction> sessionTransaction;
	int countOfFailedTransaction;
	int countOfDifferentLocation;
	@JsonIgnore
	Set<String> differentLocations;
	
	
	public String getUserId() {
		return userId;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	public List<SessionTransaction> getSessionTransaction() {
		return sessionTransaction;
	}
	public void setSessionTransaction(List<SessionTransaction> sessionTransaction) {
		this.sessionTransaction = sessionTransaction;
	}
	public int getCountOfFailedTransaction() {
		return countOfFailedTransaction;
	}
	public void setCountOfFailedTransaction(int countOfFailedTransaction) {
		this.countOfFailedTransaction = countOfFailedTransaction;
	}
	public int getCountOfDifferentLocation() {
		return countOfDifferentLocation;
	}
	public void setCountOfDifferentLocation(int countOfDifferentLocation) {
		this.countOfDifferentLocation = countOfDifferentLocation;
	}
	public Set<String> getDifferentLocations() {
		return differentLocations;
	}
	public void setDifferentLocations(Set<String> differentLocations) {
		this.differentLocations = differentLocations;
	}
	@Override
	public String toString() {
		return "UserReport [userId=" + userId + ", sessionTransaction=" + sessionTransaction
				+ ", countOfFailedTransaction=" + countOfFailedTransaction + ", countOfDifferentLocation="
				+ countOfDifferentLocation + ", differentLocations=" + differentLocations + "]";
	} 
	
	
	
}
