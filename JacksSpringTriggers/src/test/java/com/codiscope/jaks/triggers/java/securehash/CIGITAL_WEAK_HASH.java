package com.codiscope.jaks.triggers.java.securehash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/*
 Rule:
 <Rule lang="java" id="CIGITAL-WEAK-HASH">
  <!-- Importance : HIGH -->
  <Category>Weak Cryptographic Hash</Category>
  <Title>Use of MD5 Hash Algorithm</Title>
  <Description>Weak cryptographic hashes cannot guarantee data integrity and
   should not be used in security-critical contexts.</Description>
    <Match>
      <QualifiedName>java.security.MessageDigest</QualifiedName>
      <Method>getInstance</Method>
      <Argument comparator="regex" type="String" value="(?i)\bMD2\b|\bMD5\b|\b(SHA-1)$|\b(SHA)$|\b(SHA-128)$">0</Argument>
    </Match>
    <Standards>
      <Standard file="crypto-weak-hash.xml">
       <Context>J2EE</Context>
      </Standard>
    </Standards>    
</Rule>
*/
public class CIGITAL_WEAK_HASH {
	
	MessageDigest md;
	public void test() throws NoSuchAlgorithmException {
		
		md = MessageDigest.getInstance("MD2");
		
		md = MessageDigest.getInstance("MD5");
		
		md = MessageDigest.getInstance("SHA-1");
		
		md = MessageDigest.getInstance("SHA");
		
		md = MessageDigest.getInstance("SHA-128");
	}
}
