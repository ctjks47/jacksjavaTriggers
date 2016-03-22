<?xml version="1.0" encoding="UTF-8"?>

<!-- Rule Id = SEC-SS-FILTER-2 -->
<beans:beans xmlns="http://www.springframework.org/schema/security"
  xmlns:beans="http://www.springframework.org/schema/beans"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://www.springframework.org/schema/beans
    				  http://www.springframework.org/schema/beans/spring-beans-3.0.xsd
					  http://www.springframework.org/schema/security
                      http://www.springframework.org/schema/security/spring-security.xsd">
           
  <http pattern="resources" security="none" />

<http pattern="/static/**" security="none"/>

<http pattern="/loggedout.jsp*" security="none"/>

<http pattern="/**" disable-url-rewriting="false" />

<http>
<intercept-url pattern="/login.jsp" access="ROLE_USER" requires-channel="any"/>
</http>
<http>
<intercept-url pattern="/**" access="ROLE_USER" requires-channel="any"/>
</http>

<http><intercept-url pattern="/**" access="permitAll" />
</http>


<debug />

</beans:beans> 
 

