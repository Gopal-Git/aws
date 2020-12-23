package aws.frauddetection.analysis.model;

/**
 * @author CEP-A41
 *
 */
public class SessionTransaction {

	int countOfTransactionInSession;
	String sessionId;
	public int getCountOfTransactionInSession() {
		return countOfTransactionInSession;
	}
	public void setCountOfTransactionInSession(int countOfTransactionInSession) {
		this.countOfTransactionInSession = countOfTransactionInSession;
	}
	public String getSessionId() {
		return sessionId;
	}
	public void setSessionId(String sessionId) {
		this.sessionId = sessionId;
	}
	@Override
	public String toString() {
		return "SessionTransaction [countOfTransactionInSession=" + countOfTransactionInSession + ", sessionId="
				+ sessionId + "]";
	}
	
	
}
