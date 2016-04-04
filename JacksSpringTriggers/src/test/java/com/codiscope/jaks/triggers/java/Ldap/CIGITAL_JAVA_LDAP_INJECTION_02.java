package com.codiscope.jaks.triggers.java.Ldap;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.servlet.http.HttpServletRequest;


/*
 Rule:
 	<Rule id="CIGITAL-JAVA-LDAP-INJECTION-02" lang="java">
		<!-- IMPORTANCE: HIGH -->
		<Category>LDAP Injection</Category>
		<Title>Untrusted data used to build LDAP query</Title>
		<Description>LDAP search filter might be constructed using untrusted user input.</Description>
		<Match>
			<QualifiedName><![CDATA[^javax\.naming\.directory\.BasicAttributes?$]]></QualifiedName>
			<Argument taint="WEB">1</Argument>
		</Match>
		<Standards>
			<Standard file="ldap-injection.xml">
				<Context>J2EE</Context>
			</Standard>
		</Standards>
	</Rule>
 */
public class CIGITAL_JAVA_LDAP_INJECTION_02 {
	HttpServletRequest request = null;
	
	public void testWeb() {        
        Attributes userAttributes = new BasicAttributes("test",  webMethod());
        
//        Attributes userAttributes1 = new BasicAttributes("test",  filesource.method1());
//        Attributes userAttributes2 = new BasicAttributes("test",  databasesource.method1());
	}
	
	public String webMethod() {
		String s01 = request.getRemoteHost();
		return s01;
	}
}
