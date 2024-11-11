# AI Prompt Fuzzer

## Introduction
The rapid adoption of AI and large language models (LLMs) across various applications has introduced a host of new security challenges, particularly around safeguarding prompt-based interactions. As these models integrate deeply into systems—powering customer support, content generation, and decision-making—they often hold sensitive data and access critical internal functions. However, there’s a significant lack of penetration testing tools designed specifically to identify and mitigate LLM-specific vulnerabilities. This leaves AI-driven systems susceptible to threats like prompt injection, where attackers manipulate prompts to reveal confidential information, bypass security protocols, or even execute unauthorized actions.

## Description
The AI Prompt Fuzzer is a Burp Suite extension that allows security professionals and testers to automatically "fuzz"/brute force an AI-based prompt by loading and testing various payloads from an external file. The extension integrates seamlessly with Burp Suite, providing a table-based interface where users can load, organize, and send a variety of payloads to an AI prompt API endpoint, helping identify vulnerabilities, edge cases, or anomalous behaviors in the model's responses.

## Compilation Instructions
You can ignore this section, if you plan to download and use the pre-compiled version (check Releases).
### Prerequisites
Ensure you have the following installed:
* Java Development Kit (JDK): Version 8 or higher.
* Apache Maven: Used to manage dependencies and build the project. You can install it from [Maven’s official site](https://maven.apache.org/).
### Download the Source Code
Download or clone the source code from the repository
```
git clone https://github.com/moha99sa/AI_Prompt_Fuzzer.git
cd AI_Prompt_Fuzzer
```
### Building the Project with Maven
Run the Maven package command to compile the project and package it into a JAR file.
```
mvn clean package
```
After the build completes, the compiled JAR file (AI_Prompt_Fuzzer.jar) will be in the target directory.

## Installation in Burp Suite
1. Open Burp Suite: Launch your Burp Suite application.
2. Navigate to the Extensions tab: In Burp, go to the Extender tab and select Extensions.
3. Add the Extension:
     - Click on Add.
     - For Extension Type, choose Java.
     - Browse to select the AI_Prompt_Fuzzer.jar file you just created.
5. Load the Extension: Click Next, and Burp Suite should load the extension. You should see a new tab labeled AI Prompt Fuzzer in the Burp Suite interface.

## Usage Instructions
### Interface Overview
After installing the extension, you’ll see a tab named AI Prompt Fuzzer in Burp Suite. The tab includes the following sections:
* **Request to be sent**: Request section where you can edit and modify the HTTP request for the target AI/LLM application. It is important to remember to add a placeholder for the fuzzing/brute force payloads. You can send requests to this section from Burp Target, Proxy, Repeater, Intruder ... etc. by using the Right click menu -> Extensions -> AI Prompt Fuzzer -> Send Request.
* **Requests and Responses Log**: A table display for some information about the requests sent to the target and their responses. The table shows the following attributes (can help in ordering/sorting results): 
  - Time: When the response received.
  - Method: The HTTP Method used.
  - URL: Targeted URL for the request.
  - Status: The HTTP status code for the response.
  - Length: The size/length of the response.
  - Potential Break: Indicator if the response triggers a potential anomaly or predefined condition. For instance, when TRUE, it indicates that the response matches the expected answer for the specific payload sent in the request.
* **Request and Response Viewer**: A text area that shows the full content of the selected request and response in the log table. Here, you can verify and check the payload sent to the server and the response received.
* **Load Payloads Button**: Allows you to upload a payload file. Payloads should be stored in an XML file, with specific format (check the attached GeneralPayloads.xml or review the Payloads and Formatting section).


