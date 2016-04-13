package com.codiscope.jaks.triggers.java.ulrredirection;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/*
 Rule:
<Rule id="CIGITAL-JAVA-URL-REDIRECT" lang="java">
		<Category>URL Redirection</Category>
		<Title>Unvalidated Redirects and Forwards</Title>
		<Description>Identifies when a URL redirect request has been made so developer can confirm that url parameter is not tainted.</Description>
		<Match>
			<QualifiedName>javax.servlet.http.HttpServletResponse</QualifiedName>
			<Method>sendRedirect</Method>
		</Match>
		<Standards>
			<Standard file="url-redirect-attack.xml">
				<Context>J2EE</Context>
			</Standard>
		</Standards>
	</Rule>
*/
public class CIGITAL_JAVA_URL_REDIRECT {
	HttpServletResponse response = null;
	HttpServletRequest request = null;
	
	public void test() throws IOException {
		
		response.sendRedirect(webMethod());
	}
	
//	public String webMethod() {
//		RequestDispatcher s01 = request.getRequestDispatcher("http://cigital.com");
//		
//		return s01.toString();
//	}
	public String webMethod() {
		String s01 = request.getRemoteHost();
		return s01;
	}
	
}

