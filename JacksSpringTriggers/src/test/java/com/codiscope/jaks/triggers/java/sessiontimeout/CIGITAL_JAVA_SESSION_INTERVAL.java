package com.codiscope.jaks.triggers.java.sessiontimeout;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/*
 Rule:
 <Rule id="CIGITAL-JAVA-SESSION-INTERVAL" lang="java">
		<Category>Code Correctness</Category>
		<Title>Too low inactive interval</Title>
		<Description>Session inactive interval is too low</Description>
		<Match>
			<QualifiedName>javax.servlet.http.HttpSession</QualifiedName>
			<Method>setMaxInactiveInterval</Method>
			<Argument value="1800" comparator="lessThanOrEqual" type="int">0</Argument>
		</Match>
		<Standards>
			<Standard file="session-management-timeout.xml">
				<Context>J2EE</Context>
			</Standard>
		</Standards>
	</Rule>
*/
public class CIGITAL_JAVA_SESSION_INTERVAL {
	HttpServletRequest request = null;
	
	public void test() {
		HttpSession session = request.getSession();
		
		session.setMaxInactiveInterval(1000);
		
		session.setMaxInactiveInterval(1800);
		
		session.setMaxInactiveInterval(1900);
	}
}
