package edu.coverter.cve;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.jena.ontology.*;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.vocabulary.RDF;

import java.io.*;

public class JsonToIndividualsConverter {
    static OntModel ontologyModel;
    static String ontologyIRI = "http://birzeit.edu/cve_schema5_0";

    public static void main(String[] args) throws FileNotFoundException {
        // Path to the JSON file
        String jsonFilePath = "C:\\M.kharma_data\\PhD\\03-Semester-2022\\Threat-modeling\\OdTM-mkharma\\cveExample1.json";
//        String jsonFilePath = "C:\\M.kharma_data\\PhD\\03-Semester-2022\\Threat-modeling\\OdTM-mkharma\\cveExample.json";

        // Load the ontology
        ontologyModel = ModelFactory.createOntologyModel();
        ontologyModel.read("C:\\M.kharma_data\\PhD\\03-Semester-2022\\Threat-modeling\\OdTM-mkharma\\CC_Ontology.owl");
//        ontologyModel.read("C:\\M.kharma_data\\PhD\\03-Semester-2022\\Threat-modeling\\OdTM-mkharma\\CVE_OntologyV2.owl");

        // Read the JSON file
        String jsonData = readJsonFile(jsonFilePath);

        // Convert JSON to individuals
        JsonObject jsonObject = JsonParser.parseString(jsonData).getAsJsonObject();
        JsonArray array = jsonObject.getAsJsonArray("List");
        for (int i = 0; i < array.size(); i++) {
            convertJsonToIndividuals(array.get(i).getAsJsonObject(), ontologyModel);
        }

        // Save the ontology to a file
        ontologyModel.write(System.out, "RDF/XML-ABBREV");
        // Uncomment the line below to save the ontology to a file
        ontologyModel.write(new FileOutputStream("generatedCVERecord.owl"), "RDF/XML-ABBREV");
        ontologyModel.write(new FileOutputStream("TURTLECVE.owl"), "TURTLE");


//        try {
//            ProcessBuilder processBuilder = new ProcessBuilder("python",
//                    ("C:\\M.kharma_data\\PhD\\03-Semester-2022\\Threat-modeling\\OdTM-mkharma\\uploadGraphDB.py"));
////        processBuilder.redirectErrorStream(true);
//            Process process = processBuilder.start();
//            int exitCode = process.waitFor();
//            System.out.println("No errors should be detected" + exitCode);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
    }

    private static String readJsonFile(String filePath) {
        StringBuilder jsonData = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                jsonData.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return jsonData.toString();
    }

    private static void convertJsonToIndividuals(JsonObject jsonObject, OntModel ontologyModel) {
        // Extract the JSON data
        JsonObject cveMetadata = jsonObject.getAsJsonObject("cveMetadata");
        JsonObject containers = jsonObject.getAsJsonObject("containers");
        JsonObject cna = containers.getAsJsonObject("cna");
        JsonObject affected = cna.getAsJsonArray("affected").get(0).getAsJsonObject();
        JsonObject credits = null;
        if (cna.getAsJsonArray("credits") != null)
            credits = cna.getAsJsonArray("credits").get(0).getAsJsonObject();
        JsonObject descriptions = cna.getAsJsonArray("descriptions").get(0).getAsJsonObject();
        JsonObject metrics = null;
        if (cna.getAsJsonArray("metrics") != null)
            metrics = cna.getAsJsonArray("metrics").get(0).getAsJsonObject();
        JsonObject problemTypes = cna.getAsJsonArray("problemTypes").get(0).getAsJsonObject();
//        JsonObject providerMetadata = cna.getAsJsonObject("providerMetadata");
        JsonObject references = cna.getAsJsonArray("references").get(0).getAsJsonObject();

//        JsonObject solutions = cna.getAsJsonArray("solutions").get(0).getAsJsonObject();
//        JsonObject source = cna.getAsJsonObject("source");
//        JsonObject timeline = cna.getAsJsonArray("timeline").get(0).getAsJsonObject();
//        String xGenerator = cna.getAsJsonObject("x_generator").get("engine").getAsString();

        // Create the CVE individual
        String cveId = cveMetadata.get("cveId").getAsString();
        Individual cveIndividual = createIndividual(ontologyIRI, "#CVE", cveId);

        Individual cveHeaderIndividual = createIndividual(ontologyIRI, "#CVEHeader", cveId);

        cveIndividual.addProperty(ontologyModel.getProperty(
                ontologyIRI + "#hasCveHeader"), cveHeaderIndividual);

        cveHeaderIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#cveId"), cveId);
        cveHeaderIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasOrgId"),
                cveMetadata.get("assignerOrgId").getAsString());
        cveHeaderIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#status"),
                cveMetadata.get("state").getAsString());
        cveHeaderIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#assignerShortName"),
                cveMetadata.get("assignerShortName").getAsString());
        cveHeaderIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#dateReserved"),
                cveMetadata.get("dateReserved").getAsString());
        cveHeaderIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#datePublished"),
                cveMetadata.get("datePublished").getAsString());

        Individual cveInformationSourceIndividual = createIndividual(ontologyIRI,
                "#CVEInformationSource", cveId); //todo check

        cveIndividual.addProperty(ontologyModel.getProperty(
                ontologyIRI + "#hasDetailsFrom"), cveInformationSourceIndividual);

        // Create the Affected individual
        Individual affectedIndividual = createIndividual(ontologyIRI,
                "#AffectedProduct", cveId);

        // Connect the CVE individual to the Affected individual
        cveInformationSourceIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasAffected"),
                affectedIndividual);

        if (affected.get("defaultStatus") != null)
            affectedIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#defaultStatus"),
                    affected.get("defaultStatus").getAsString());
        affectedIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasProduct"),
                affected.get("product").getAsString());
        affectedIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasVendor"),
                affected.get("vendor").getAsString());

        // Create the Platform individual
        String platformValue =
                removeSpecialChar(affected.getAsJsonArray("platforms"));
        Individual platformIndividual = createIndividual(ontologyIRI,
                "#Platform", platformValue);

        platformIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasName"),
                platformValue);

        // Connect the Affected individual to the Platform individual
        affectedIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasPlatform"),
                platformIndividual);

        // Create the Version individual
        JsonObject version = affected.getAsJsonArray("versions").get(0).getAsJsonObject();
        Individual versionIndividual = createIndividual(ontologyIRI,
                "#Version", removeSpecialChar(affected.getAsJsonArray("versions")));

        versionIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#status"),
                version.get("status").getAsString());
        versionIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#versionValue"),
                version.get("version").getAsString());

        // Connect the Affected individual to the Version individual
        affectedIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasVersion"),
                versionIndividual);

        if (credits != null) {
            // Create the Credit individual
            Individual creditIndividual =
                    createIndividual(ontologyIRI,
                            "#Contributer", cveId);
            // Connect the CVE individual to the Credit individual
            cveInformationSourceIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasContributer"),
                    creditIndividual);

            creditIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#lang"),
                    credits.get("lang").getAsString());
            creditIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#contributionType"),
                    credits.get("type").getAsString());
            creditIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#user"),
                    credits.get("user").getAsString());
            creditIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#contributionDesc"),
                    credits.get("value").getAsString());
        }
        // Create the Description individual
//        Individual descriptionIndividual =  createIndividual(androidOntologyIRI,
//                "#Description", cveId);

//        descriptionIndividual.addProperty(ontologyModel.getProperty(androidOntologyIRI + "#lang"),
//                descriptions.get("lang").getAsString());
//        descriptionIndividual.addProperty(ontologyModel.getProperty(androidOntologyIRI + "#value"),
//                descriptions.get("value").getAsString());

        // Connect the CVE individual to the Description individual
        cveInformationSourceIndividual.addProperty(ontologyModel.getProperty(ontologyIRI +
                        "#hasDescription"),
                descriptions.get("value").getAsString());

        if (metrics != null) {
            // Create the Metric individual
            Individual metricIndividual =
                    createIndividual(ontologyIRI,
                            "#Metric", cveId);

            metricIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#format"),
                    metrics.get("format").getAsString());

            // Create the CVSSV3 individual
            JsonObject cvssV3 = metrics.getAsJsonObject("cvssV3_1");
            Individual cvssV3Individual = ontologyModel.createIndividual(
                    ontologyIRI + "#CVSSV3_" + cveId,
                    ontologyModel.getOntClass(ontologyIRI + "#CVSSV3"));

            // Add properties to the CVSSV3 individual todo
//        cvssV3Individual.addProperty(RDF.type, ontologyModel.getOntClass(androidOntologyIRI + "#CVSSV3"));
            cvssV3Individual.addProperty(ontologyModel.getProperty(ontologyIRI + "#attackComplexity"),
                    cvssV3.get("attackComplexity").getAsString());
            cvssV3Individual.addProperty(ontologyModel.getProperty(ontologyIRI + "#attackVector"),
                    cvssV3.get("attackVector").getAsString());
            cvssV3Individual.addProperty(ontologyModel.getProperty(ontologyIRI + "#availabilityImpact"),
                    cvssV3.get("availabilityImpact").getAsString());
            cvssV3Individual.addProperty(ontologyModel.getProperty(ontologyIRI + "#baseScore"),
                    cvssV3.get("baseScore").getAsString());
            cvssV3Individual.addProperty(ontologyModel.getProperty(ontologyIRI + "#baseSeverity"),
                    cvssV3.get("baseSeverity").getAsString());
            cvssV3Individual.addProperty(ontologyModel.getProperty(ontologyIRI + "#confidentialityImpact"),
                    cvssV3.get("confidentialityImpact").getAsString());
            cvssV3Individual.addProperty(ontologyModel.getProperty(ontologyIRI + "#integrityImpact"),
                    cvssV3.get("integrityImpact").getAsString());
            cvssV3Individual.addProperty(ontologyModel.getProperty(ontologyIRI + "#privilegesRequired"),
                    cvssV3.get("privilegesRequired").getAsString());
            cvssV3Individual.addProperty(ontologyModel.getProperty(ontologyIRI + "#scope"),
                    cvssV3.get("scope").getAsString());
            cvssV3Individual.addProperty(ontologyModel.getProperty(ontologyIRI + "#userInteraction"),
                    cvssV3.get("userInteraction").getAsString());

            // Connect the Metric individual to the CVSSV3 individual
            metricIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasCVSSV3"),
                    cvssV3Individual);

            // Connect the CVE individual to the Metric individual
            cveInformationSourceIndividual.addProperty(
                    ontologyModel.getProperty(ontologyIRI + "#hasMetric"),
                    metricIndividual);
        }
        // Create the ProblemType individual


        JsonObject problemTypeData = problemTypes.getAsJsonArray("descriptions").get(0).getAsJsonObject();
        // Add properties to the ProblemTypeData individual
        if (problemTypeData.get("cweId") != null) {
            Individual problemTypeDataIndividual =
                    createIndividual(ontologyIRI,
                            "#CWE", problemTypeData.get("cweId").getAsString());
            problemTypeDataIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#cweId"),
                    problemTypeData.get("cweId").getAsString());
            problemTypeDataIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#description"),
                    problemTypeData.get("description").getAsString());
//            problemTypeDataIndividual.addProperty(ontologyModel.getProperty(androidOntologyIRI + "#lang"),
//                    problemTypeData.get("lang").getAsString());
            cveInformationSourceIndividual.addProperty(
                    ontologyModel.getProperty(ontologyIRI + "#hasCWE"),
                    problemTypeDataIndividual);
        }
//        // Create the ProviderMetadata individual
//        Individual providerMetadataIndividual = ontologyModel.createIndividual(
//                androidOntologyIRI + "#ProviderMetadata_" + cveId,
//                ontologyModel.getOntClass(androidOntologyIRI + "#PROVIDERMETADATA"));
//
//        // Add properties to the ProviderMetadata individual
//        providerMetadataIndividual.addProperty(RDF.type, ontologyModel.getOntClass(androidOntologyIRI + "#PROVIDERMETADATA"));
//        providerMetadataIndividual.addProperty(ontologyModel.getProperty(androidOntologyIRI + "#url"),
//                providerMetadata.get("url").getAsString());
//        providerMetadataIndividual.addProperty(ontologyModel.getProperty(androidOntologyIRI + "#providerName"),
//                providerMetadata.get("providerName").getAsString());
//
//        // Connect the CVE individual to the ProviderMetadata individual
//        cveIndividual.addProperty(ontologyModel.getProperty(androidOntologyIRI + "#hasProviderMetadata"),
//                providerMetadataIndividual);

        // Create the Reference individual
        Individual referenceIndividual =
                createIndividual(ontologyIRI,
                        "#Reference", cveId);

        referenceIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasURL"),
                references.get("url").getAsString());

        // Connect the CVE individual to the Reference individual
        cveInformationSourceIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasReference"),
                referenceIndividual);
//
//        // Create the Solution individual


        try {
            // Create the solutions individual
            if(cna.getAsJsonArray("solutions")!=null) {
                JsonObject solutions = cna.getAsJsonArray("solutions").get(0).getAsJsonObject();
                Individual solutionIndividual =
                        createIndividual(ontologyIRI,
                                "#Solution", cveId);

                solutionIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasDescription"),
                        solutions.get("value").getAsString());

                // Connect the CVE individual to the Reference individual
                cveInformationSourceIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasSolution"),
                        solutionIndividual);

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            if(cna.getAsJsonArray("timeline")!=null) {
                // Create the reportingHistoryIndividual individual
                JsonObject solutions = cna.getAsJsonArray("timeline").get(0).getAsJsonObject();
                Individual reportingHistoryIndividual =
                        createIndividual(ontologyIRI,
                                "#ReportingHistory", cveId);

                reportingHistoryIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasStatus"),
                        solutions.get("value").getAsString());
                reportingHistoryIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasTime"),
                        solutions.get("time").getAsString());

                // Connect the CVE individual to the Reference individual
                cveInformationSourceIndividual.addProperty(
                        ontologyModel.getProperty(ontologyIRI + "#hasReportingHistory"),
                        reportingHistoryIndividual);

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            if(cna.getAsJsonArray("workarounds")!=null) {
                // Create the solutions individual
                JsonObject solutions = cna.getAsJsonArray("workarounds").get(0).getAsJsonObject();
                Individual solutionIndividual =
                        createIndividual(ontologyIRI,
                                "#Workaround", cveId);

                solutionIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasDescription"),
                        solutions.get("value").getAsString());

                // Connect the CVE individual to the Reference individual
                cveInformationSourceIndividual.addProperty(ontologyModel.getProperty(ontologyIRI + "#hasWorkaround"),
                        solutionIndividual);

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Save the ontology model to a file
        try {
            FileOutputStream outputStream = new FileOutputStream("generated_cve_ontology.owl");
            ontologyModel.write(outputStream, "RDF/XML-ABBREV");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        System.out.println("Ontology creation completed.");
    }

    private static String getClearText(String id) {
        return id.replaceAll("[^a-zA-Z0-9_.-]", "");
    }

    private static Individual createIndividual(String iri, String name, String id) {
        id = getClearText(id);
        Individual individual = ontologyModel.createIndividual(
                iri + name + "_" + id,
                ontologyModel.getOntClass(
                        iri +
                                name));
        individual.addProperty(RDF.type,
                ontologyModel.getOntClass(
                        iri +
                                name));
        return individual;
    }

    private static String removeSpecialChar(JsonArray platforms) {
        String s = "Centos";
        if (platforms != null)
            for (JsonElement platform : platforms) {
                if (platform.toString().length() > 0)
                    s += "_" + platform.toString();
                else if (platform.getAsString() != null && platform.getAsJsonObject().get("version").getAsString().length() > 0)
                    s += "_" + platform.getAsJsonObject().get("version").getAsString();
            }
        return s.replaceAll("\"", "")
                .replaceAll("\\[", "")
                .replaceAll("]", "")
                .replaceAll(":", "")
                .replaceAll("\\.", "")
                .replaceAll("\\{", "")
                .replaceAll("}", "")
                .replaceAll(" ", "_")
                .replaceAll(",", "_").replaceFirst("_", "");
    }
}
