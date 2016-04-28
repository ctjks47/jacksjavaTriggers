package com.codiscope.jaks.triggers.java.commandInjection;

import java.io.File;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Map;
import java.util.Scanner;

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
	Scanner sc = new Scanner(System.in);
	Runtime rt = Runtime.getRuntime();
	ProcessBuilder pb;

	public void testExecMethod() throws IOException {
		// rt.exec(websource.method1());
		rt.exec(webMethod());
	}

	public void testWebProcessBuilder() throws IOException {

		new ProcessBuilder(webMethod()); // process build getting input from
	}

	public void testCommandMethod(){
		
		pb.command(webMethod()); //   command taint
	}
	
	public void testDirectoryMethod(){
		
		File file = new File(webMethod());
		pb.directory(file); // command taint;
	}
	public String webMethod() {
		String s01 = request.getRemoteHost();
		return s01;
	}
}