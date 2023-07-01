package edu.coverter.cve;

//import org.json.JSONArray;
//import org.json.JSONObject;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;

public class CveV5Parser {
    public static void main(String[] args) {
        // JSON file path
        String filePath = "path/to/your/json/file.json";

        // Create ObjectMapper instance
        ObjectMapper objectMapper = new ObjectMapper();

        try {
            // Read JSON file and parse it into CVE object
            CVE cve = objectMapper.readValue(
                    json.replace("x_generator", "xgenerator")/*new File(filePath)*/, CVE.class);

            // Access the parsed data
            System.out.println("CVE ID: " + cve.getCveMetadata().getCveId());
            System.out.println("Assigner Short Name: " + cve.getCveMetadata().getAssignerShortName());
            System.out.println("Date Published: " + cve.getCveMetadata().getDatePublished());
            System.out.println("Title: " + cve.getContainers().getCna().getTitle());
            System.out.println("getProblemTypes: " + cve.getContainers().getCna().getProblemTypes());
//            System.out.println("CVE ID: " + cve.get);
            // Access other attributes as needed

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

   public static String json = "{\n" +
            "    \"dataType\": \"CVE_RECORD\",\n" +
            "    \"dataVersion\": \"5.0\",\n" +
            "    \"cveMetadata\": {\n" +
            "        \"cveId\": \"CVE-2023-0001\",\n" +
            "        \"assignerOrgId\": \"d6c1279f-00f6-4ef7-9217-f89ffe703ec0\",\n" +
            "        \"state\": \"PUBLISHED\",\n" +
            "        \"assignerShortName\": \"palo_alto\",\n" +
            "        \"dateReserved\": \"2022-10-27T18:47:48.958Z\",\n" +
            "        \"datePublished\": \"2023-02-08T17:20:20.774Z\"\n" +
            "    },\n" +
            "    \"containers\": {\n" +
            "        \"cna\": {\n" +
            "            \"affected\": [\n" +
            "                {\n" +
            "                    \"defaultStatus\": \"unaffected\",\n" +
            "                    \"platforms\": [\n" +
            "                        \"Windows\"\n" +
            "                    ],\n" +
            "                    \"product\": \"Cortex XDR agent\",\n" +
            "                    \"vendor\": \"Palo Alto Networks\",\n" +
            "                    \"versions\": [\n" +
            "                        {\n" +
            "                            \"status\": \"unaffected\",\n" +
            "                            \"version\": \"7.9 All\"\n" +
            "                        },\n" +
            "                        {\n" +
            "                            \"status\": \"unaffected\",\n" +
            "                            \"version\": \"7.8 All\"\n" +
            "                        },\n" +
            "                        {\n" +
            "                            \"changes\": [\n" +
            "                                {\n" +
            "                                    \"at\": \"7.5.101-CE\",\n" +
            "                                    \"status\": \"unaffected\"\n" +
            "                                }\n" +
            "                            ],\n" +
            "                            \"lessThan\": \"7.5.101-CE\",\n" +
            "                            \"status\": \"affected\",\n" +
            "                            \"version\": \"7.5\",\n" +
            "                            \"versionType\": \"custom\"\n" +
            "                        },\n" +
            "                        {\n" +
            "                            \"status\": \"unaffected\",\n" +
            "                            \"version\": \"5.0 All\"\n" +
            "                        }\n" +
            "                    ]\n" +
            "                }\n" +
            "            ],\n" +
            "            \"credits\": [\n" +
            "                {\n" +
            "                    \"lang\": \"en\",\n" +
            "                    \"type\": \"finder\",\n" +
            "                    \"user\": \"00000000-0000-4000-9000-000000000000\",\n" +
            "                    \"value\": \"Palo Alto Networks thanks Robert McCallum (M42D) for discovering and reporting this issue.\"\n" +
            "                }\n" +
            "            ],\n" +
            "            \"datePublic\": \"2023-02-08T17:00:00.000Z\",\n" +
            "            \"descriptions\": [\n" +
            "                {\n" +
            "                    \"lang\": \"en\",\n" +
            "                    \"supportingMedia\": [\n" +
            "                        {\n" +
            "                            \"base64\": false,\n" +
            "                            \"type\": \"text/html\",\n" +
            "                            \"value\": \"An information exposure vulnerability in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local system administrator to disclose the admin password for the agent in cleartext, which bad actors can then use to execute privileged cytool commands that disable or uninstall the agent.\"\n" +
            "                        }\n" +
            "                    ],\n" +
            "                    \"value\": \"An information exposure vulnerability in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local system administrator to disclose the admin password for the agent in cleartext, which bad actors can then use to execute privileged cytool commands that disable or uninstall the agent.\"\n" +
            "                }\n" +
            "            ],\n" +
            "            \"metrics\": [\n" +
            "                {\n" +
            "                    \"cvssV3_1\": {\n" +
            "                        \"attackComplexity\": \"LOW\",\n" +
            "                        \"attackVector\": \"LOCAL\",\n" +
            "                        \"availabilityImpact\": \"HIGH\",\n" +
            "                        \"baseScore\": 6,\n" +
            "                        \"baseSeverity\": \"MEDIUM\",\n" +
            "                        \"confidentialityImpact\": \"HIGH\",\n" +
            "                        \"integrityImpact\": \"NONE\",\n" +
            "                        \"privilegesRequired\": \"HIGH\",\n" +
            "                        \"scope\": \"UNCHANGED\",\n" +
            "                        \"userInteraction\": \"NONE\",\n" +
            "                        \"vectorString\": \"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H\",\n" +
            "                        \"version\": \"3.1\"\n" +
            "                    },\n" +
            "                    \"format\": \"CVSS\",\n" +
            "                    \"scenarios\": [\n" +
            "                        {\n" +
            "                            \"lang\": \"en\",\n" +
            "                            \"value\": \"GENERAL\"\n" +
            "                        }\n" +
            "                    ]\n" +
            "                }\n" +
            "            ],\n" +
            "            \"problemTypes\": [\n" +
            "                {\n" +
            "                    \"descriptions\": [\n" +
            "                        {\n" +
            "                            \"cweId\": \"CWE-319\",\n" +
            "                            \"description\": \"CWE-319 Cleartext Transmission of Sensitive Information\",\n" +
            "                            \"lang\": \"en\",\n" +
            "                            \"type\": \"CWE\"\n" +
            "                        }\n" +
            "                    ]\n" +
            "                }\n" +
            "            ],\n" +
            "            \"providerMetadata\": {\n" +
            "                \"orgId\": \"d6c1279f-00f6-4ef7-9217-f89ffe703ec0\",\n" +
            "                \"shortName\": \"palo_alto\",\n" +
            "                \"dateUpdated\": \"2023-02-08T17:20:20.774Z\"\n" +
            "            },\n" +
            "            \"references\": [\n" +
            "                {\n" +
            "                    \"url\": \"https://security.paloaltonetworks.com/CVE-2023-0001\"\n" +
            "                }\n" +
            "            ],\n" +
            "            \"solutions\": [\n" +
            "                {\n" +
            "                    \"lang\": \"en\",\n" +
            "                    \"supportingMedia\": [\n" +
            "                        {\n" +
            "                            \"base64\": false,\n" +
            "                            \"type\": \"text/html\",\n" +
            "                            \"value\": \"This issue is fixed in Cortex XDR agent 7.5.101-CE and all later supported Cortex XDR agent versions. (Cortex XDR agent 5.0 is not impacted.)<br><br>After you upgrade to a fixed version of the Cortex XDR agent, you must change the agent admin password in case it was already disclosed to users.\"\n" +
            "                        }\n" +
            "                    ],\n" +
            "                    \"value\": \"This issue is fixed in Cortex XDR agent 7.5.101-CE and all later supported Cortex XDR agent versions. (Cortex XDR agent 5.0 is not impacted.)\\n\\nAfter you upgrade to a fixed version of the Cortex XDR agent, you must change the agent admin password in case it was already disclosed to users.\"\n" +
            "                }\n" +
            "            ],\n" +
            "            \"source\": {\n" +
            "                \"defect\": [\n" +
            "                    \"CPATR-13152\"\n" +
            "                ],\n" +
            "                \"discovery\": \"INTERNAL\"\n" +
            "            },\n" +
            "            \"timeline\": [\n" +
            "                {\n" +
            "                    \"lang\": \"en\",\n" +
            "                    \"time\": \"2023-02-08T17:00:00.000Z\",\n" +
            "                    \"value\": \"Initial publication\"\n" +
            "                }\n" +
            "            ],\n" +
            "            \"title\": \"Cortex XDR Agent: Cleartext Exposure of Agent Admin Password\",\n" +
            "            \"workarounds\": [\n" +
            "                {\n" +
            "                    \"lang\": \"en\",\n" +
            "                    \"supportingMedia\": [\n" +
            "                        {\n" +
            "                            \"base64\": false,\n" +
            "                            \"type\": \"text/html\",\n" +
            "                            \"value\": \"There are no known workarounds for this issue.\"\n" +
            "                        }\n" +
            "                    ],\n" +
            "                    \"value\": \"There are no known workarounds for this issue.\"\n" +
            "                }\n" +
            "            ],\n" +
            "            \"x_generator\": {\n" +
            "                \"engine\": \"Vulnogram 0.1.0-dev\"\n" +
            "            }\n" +
            "        }\n" +
            "    }\n" +
            "}";

}


//public class CVESchemaParser {
//
//    public static void main(String[] args) {

//        JSONObject jsonObject = new JSONObject(json);
//
//        // Extract CVE ID
//        String cveId = jsonObject.getJSONObject("cveMetadata").getString("cveId");
//        System.out.println("CVE ID: " + cveId);
//
//        // Extract vendor and product
//        JSONObject container = jsonObject.getJSONObject("containers").getJSONObject("cna").getJSONArray("affected").getJSONObject(0);
//        String vendor = container.getString("vendor");
//        String product = container.getString("product");
//        System.out.println("Vendor: " + vendor);
//        System.out.println("Product: " + product);
//
//        // Extract affected versions
//        JSONArray versions = container.getJSONArray("versions");
//        for (int i = 0; i < versions.length(); i++) {
//            JSONObject versionObj = versions.getJSONObject(i);
//            String version = versionObj.getString("version");
//            String status = versionObj.getString("status");
//            System.out.println("Version: " + version);
//            System.out.println("Status: " + status);
//        }
//
//        // Extract description
//        JSONArray descriptions = container.getJSONArray("descriptions");
//        for (int i = 0; i < descriptions.length(); i++) {
//            JSONObject descriptionObj = descriptions.getJSONObject(i);
//            String description = descriptionObj.getString("value");
//            System.out.println("Description: " + description);
//        }
//
//        // Extract CVSS score
//        JSONArray metrics = container.getJSONArray("metrics");
//        JSONObject cvssObj = metrics.getJSONObject(0).getJSONObject("cvssV3_1");
//        String baseScore = String.valueOf(cvssObj.getDouble("baseScore"));
//        System.out.println("CVSS Base Score: " + baseScore);
//
//        // Extract references
//        JSONArray references = container.getJSONArray("references");
//        for (int i = 0; i < references.length(); i++) {
//            JSONObject referenceObj = references.getJSONObject(i);
//            String url = referenceObj.getString("url");
//            System.out.println("Reference URL: " + url);
//        }
//    }
//}

