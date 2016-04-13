package com.codiscope.jaks.triggers.java.commandInjection;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Enumeration;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;


/*
 Rule:
 <Rule id="CIGITAL-COMMAND-INJECTION-EXEC" lang="java">
 <!-- IMPORTANCE: HIGH -->
 <Category>Command Injection</Category>
 <Title>Use of untrusted data to execute commannds</Title>
 <Description>Runtime.exec() method might be using untrusted data from the user.</Description>
 <Match>
 <QualifiedName><![CDATA[^java\.lang\.Runtime$]]></QualifiedName>
 <Method><![CDATA[^exec$]]></Method>
 <Argument taint="UNTRUSTED">0</Argument>
 </Match>
 <Standards>
 <Standard file="command-injection.xml">
 <Context>J2EE</Context>
 </Standard>
 </Standards>
 </Rule>
 */
public class CIGITAL_COMMAND_INJECTION_EXEC {
	HttpServletRequest request = null;
	Runtime rt = Runtime.getRuntime();
	ProcessBuilder pb;
	public void testWeb() throws IOException {
		// rt.exec(websource.method1());
		rt.exec(webMethod());
	}
	
	public void testWebProcessBuilder() throws IOException {
		pb = new ProcessBuilder(webMethod(), "myArg1", "myArg2");
		
		pb = new ProcessBuilder(webMethod2(), "myArg1", "myArg2");
		
		pb = new ProcessBuilder(webMethod3(), "myArg1", "myArg2");
		
		pb = new ProcessBuilder(webMethod4(), "myArg1", "myArg2");
	}
	public String webMethod() {
		String s01 = request.getRemoteHost();
		return s01;
	}
	
	public String webMethod2() {
		String[] s01 = request.getParameterValues("abc");
		return s01.toString();
	}
	
	public String webMethod3() {
		Enumeration s01 = request.getParameterNames();
		return s01.toString();
	}
	
	public String webMethod4() {
		Map s01 = request.getParameterMap();
		return s01.toString();
	}
}