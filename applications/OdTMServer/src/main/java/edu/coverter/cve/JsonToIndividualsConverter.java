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
    public static void main(String[] args) {
        // Path to the JSON file
        String jsonFilePath = "C:\\M.kharma_data\\PhD\\03-Semester-2022\\Threat-modeling\\OdTM-mkharma\\cveExample.csv";

        // Load the ontology
        OntModel ontologyModel = ModelFactory.createOntologyModel();
        ontologyModel.read("C:\\M.kharma_data\\PhD\\03-Semester-2022\\Threat-modeling\\OdTM-mkharma\\CVE_OntologyV2.owl");

        // Read the JSON file
        String jsonData = readJsonFile(jsonFilePath);

        // Convert JSON to individuals
        JsonObject jsonObject = JsonParser.parseString(jsonData).getAsJsonObject();
        convertJsonToIndividuals(jsonObject, ontologyModel);

        // Save the ontology to a file
        ontologyModel.write(System.out, "RDF/XML");
        // Uncomment the line below to save the ontology to a file
        // ontologyModel.write("path/to/save/ontology.owl", "RDF/XML");
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
        JsonObject credits = cna.getAsJsonArray("credits").get(0).getAsJsonObject();
        JsonObject descriptions = cna.getAsJsonArray("descriptions").get(0).getAsJsonObject();
        JsonObject metrics = cna.getAsJsonArray("metrics").get(0).getAsJsonObject();
        JsonObject problemTypes = cna.getAsJsonArray("problemTypes").get(0).getAsJsonObject();
        JsonObject providerMetadata = cna.getAsJsonObject("providerMetadata");
        JsonObject references = cna.getAsJsonArray("references").get(0).getAsJsonObject();
        JsonObject solutions = cna.getAsJsonArray("solutions").get(0).getAsJsonObject();
        JsonObject source = cna.getAsJsonObject("source");
        JsonObject timeline = cna.getAsJsonArray("timeline").get(0).getAsJsonObject();
        String xGenerator = cna.getAsJsonObject("x_generator").get("engine").getAsString();

        // Create the CVE individual
        String cveId = cveMetadata.get("cveId").getAsString();
        Individual cveIndividual = ontologyModel.createIndividual("http://birzeit.edu/cve_schema5_0#" + cveId,
                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#CVE_RECORD"));

        // Add properties to the CVE individual
        cveIndividual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#CVE_RECORD"));
        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#cveId"), cveId);
        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#assignerOrgId"),
                cveMetadata.get("assignerOrgId").getAsString());
        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#state"),
                cveMetadata.get("state").getAsString());
        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#assignerShortName"),
                cveMetadata.get("assignerShortName").getAsString());
        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#dateReserved"),
                cveMetadata.get("dateReserved").getAsString());
        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#datePublished"),
                cveMetadata.get("datePublished").getAsString());

        // Create the Affected individual
        Individual affectedIndividual = ontologyModel.createIndividual(
                "http://birzeit.edu/cve_schema5_0#Affected_" + cveId,
                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#Affected"));

        // Add properties to the Affected individual
        affectedIndividual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#AFFECTED"));
        affectedIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#defaultStatus"),
                affected.get("defaultStatus").getAsString());
        affectedIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#product"),
                affected.get("product").getAsString());
        affectedIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#vendor"),
                affected.get("vendor").getAsString());

        // Create the Platform individual
        String platformValue =
                removeSpecialChar(affected.getAsJsonArray("platforms"));
        Individual platformIndividual = ontologyModel.createIndividual(
                "http://birzeit.edu/cve_schema5_0#Platform_" + platformValue,
                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#PLATFORM"));

        // Add properties to the Platform individual
        platformIndividual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#PLATFORM"));
        platformIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#platformValue"),
                platformValue);

        // Connect the Affected individual to the Platform individual
        affectedIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasPlatform"),
                platformIndividual);

        // Create the Version individual
        JsonObject version = affected.getAsJsonArray("versions").get(0).getAsJsonObject();
        Individual versionIndividual = ontologyModel.createIndividual(
                "http://birzeit.edu/cve_schema5_0#Versions_" +
                        removeSpecialChar(affected.getAsJsonArray("versions")),
                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#VERSIONS"));

        // Add properties to the Version individual
        versionIndividual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#VERSIONS"));
        versionIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#status"),
                version.get("status").getAsString());
        versionIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#versionValue"),
                version.get("version").getAsString());

        // Connect the Affected individual to the Version individual
        affectedIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasVersion"),
                versionIndividual);

        // Connect the CVE individual to the Affected individual
        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasAffected"),
                affectedIndividual);

        // Create the Credit individual
        Individual creditIndividual = ontologyModel.createIndividual(
                "http://birzeit.edu/cve_schema5_0#Credit_" + cveId,
                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#CREDITS"));

        // Add properties to the Credit individual
        creditIndividual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#CREDITS"));
        creditIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#lang"),
                credits.get("lang").getAsString());
        creditIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#type"),
                credits.get("type").getAsString());
        creditIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#user"),
                credits.get("user").getAsString());
        creditIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#value"),
                credits.get("value").getAsString());

        // Connect the CVE individual to the Credit individual
        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasCredit"),
                creditIndividual);

        // Create the Description individual
        Individual descriptionIndividual = ontologyModel.createIndividual(
                "http://birzeit.edu/cve_schema5_0#Description_" + cveId,
                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#DESCRIPTIONS"));

        // Add properties to the Description individual todo
//        descriptionIndividual.addProperty(RDF.type,
//                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#DESCRIPTIONS"));
        descriptionIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#lang"),
                descriptions.get("lang").getAsString());
        descriptionIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#value"),
                descriptions.get("value").getAsString());

        // Connect the CVE individual to the Description individual
        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasDescription"),
                descriptionIndividual);

        // Create the Metric individual
        Individual metricIndividual = ontologyModel.createIndividual(
                "http://birzeit.edu/cve_schema5_0#Metric_" + cveId,
                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#METRICS"));

        // Add properties to the Metric individual
        metricIndividual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#METRICS"));
        metricIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#format"),
                metrics.get("format").getAsString());

        // Create the CVSSV3 individual
        JsonObject cvssV3 = metrics.getAsJsonObject("cvssV3_1");
        Individual cvssV3Individual = ontologyModel.createIndividual(
                "http://birzeit.edu/cve_schema5_0#CVSSV3_" + cveId,
                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#CVSSV3"));

        // Add properties to the CVSSV3 individual todo
//        cvssV3Individual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#CVSSV3"));
        cvssV3Individual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#attackComplexity"),
                cvssV3.get("attackComplexity").getAsString());
        cvssV3Individual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#attackVector"),
                cvssV3.get("attackVector").getAsString());
        cvssV3Individual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#availabilityImpact"),
                cvssV3.get("availabilityImpact").getAsString());
        cvssV3Individual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#baseScore"),
                cvssV3.get("baseScore").getAsString());
        cvssV3Individual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#baseSeverity"),
                cvssV3.get("baseSeverity").getAsString());
        cvssV3Individual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#confidentialityImpact"),
                cvssV3.get("confidentialityImpact").getAsString());
        cvssV3Individual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#integrityImpact"),
                cvssV3.get("integrityImpact").getAsString());
        cvssV3Individual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#privilegesRequired"),
                cvssV3.get("privilegesRequired").getAsString());
        cvssV3Individual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#scope"),
                cvssV3.get("scope").getAsString());
        cvssV3Individual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#userInteraction"),
                cvssV3.get("userInteraction").getAsString());

        // Connect the Metric individual to the CVSSV3 individual
        metricIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasCVSSV3"),
                cvssV3Individual);

        // Connect the CVE individual to the Metric individual
        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasMetric"),
                metricIndividual);

        // Create the ProblemType individual
        Individual problemTypeIndividual = ontologyModel.createIndividual(
                "http://birzeit.edu/cve_schema5_0#ProblemType_" + cveId,
                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#PROBLEM_TYPES"));

        // Add properties to the ProblemType individual
        problemTypeIndividual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#PROBLEM_TYPES"));
        problemTypeIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#lang"),
                problemTypes.getAsJsonArray("descriptions").get(0).getAsJsonObject()
                        .get("lang").getAsString());

        // Create the ProblemTypeData individual
        JsonObject problemTypeData = problemTypes.getAsJsonArray("descriptions").get(0).getAsJsonObject();
        Individual problemTypeDataIndividual = ontologyModel.createIndividual(
                "http://birzeit.edu/cve_schema5_0#PROBLEMTYPEDATADESCRIPTIONS_" + cveId,
                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#PROBLEMTYPEDATADESCRIPTIONS"));

        // Add properties to the ProblemTypeData individual
        problemTypeDataIndividual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#PROBLEMTYPEDATADESCRIPTIONS"));
        problemTypeDataIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#cweId"),
                problemTypeData.get("cweId").getAsString());
        problemTypeDataIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#description"),
                problemTypeData.get("description").getAsString());
        problemTypeDataIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#lang"),
                problemTypeData.get("lang").getAsString());

        // Connect the ProblemType individual to the ProblemTypeData individual
        problemTypeIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasProblemTypeData"),
                problemTypeDataIndividual);
//
        // Connect the CVE individual to the ProblemType individual
        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasProblemType"),
                problemTypeIndividual);

//        // Create the ProviderMetadata individual
//        Individual providerMetadataIndividual = ontologyModel.createIndividual(
//                "http://birzeit.edu/cve_schema5_0#ProviderMetadata_" + cveId,
//                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#PROVIDER_METADATA"));
//
//        // Add properties to the ProviderMetadata individual
//        providerMetadataIndividual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#PROVIDER_METADATA"));
//        providerMetadataIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#url"),
//                providerMetadata.get("url").getAsString());
//        providerMetadataIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#providerName"),
//                providerMetadata.get("providerName").getAsString());
//
//        // Connect the CVE individual to the ProviderMetadata individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasProviderMetadata"),
//                providerMetadataIndividual);

        // Create the Reference individual
        Individual referenceIndividual = ontologyModel.createIndividual(
                "http://birzeit.edu/cve_schema5_0#Reference_" + cveId,
                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#REFERENCES"));

        // Add properties to the Reference individual
        referenceIndividual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#REFERENCES"));
        referenceIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#url"),
                references.get("url").getAsString());

        // Connect the CVE individual to the Reference individual
        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasReference"),
                referenceIndividual);
//
//        // Create the Solution individual
//        Individual solutionIndividual = ontologyModel.createIndividual(
//                "http://birzeit.edu/cve_schema5_0#Solution_" + cveId,
//                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#Solution"));
//
//        // Add properties to the Solution individual
//        solutionIndividual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#Solution"));
//        solutionIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#lang"),
//                solutions.get("lang").getAsString());
//        solutionIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#value"),
//                solutions.get("value").getAsString());
//
//        // Connect the CVE individual to the Solution individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasSolution"),
//                solutionIndividual);
//
//        // Create the Source individual
//        Individual sourceIndividual = ontologyModel.createIndividual(
//                "http://birzeit.edu/cve_schema5_0#Source_" + cveId,
//                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#Source"));
//
//        // Add properties to the Source individual
//        sourceIndividual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#Source"));
//        sourceIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#lang"),
//                source.get("lang").getAsString());
//        sourceIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#name"),
//                source.get("name").getAsString());
//
//        // Connect the CVE individual to the Source individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasSource"),
//                sourceIndividual);
//
//        // Create the Timeline individual
//        Individual timelineIndividual = ontologyModel.createIndividual(
//                "http://birzeit.edu/cve_schema5_0#Timeline_" + cveId,
//                ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#Timeline"));
//
//        // Add properties to the Timeline individual
//        timelineIndividual.addProperty(RDF.type, ontologyModel.getOntClass("http://birzeit.edu/cve_schema5_0#Timeline"));
//        timelineIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#description"),
//                timeline.get("description").getAsString());
//        timelineIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#event"),
//                timeline.get("event").getAsString());
//
//        // Connect the CVE individual to the Timeline individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#hasTimeline"),
//                timelineIndividual);
//
//        // Add the x_generator property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_generator"),
//                cveMetadata.get("x_generator").getAsString());
//
//        // Add the x_id property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_id"),
//                cveMetadata.get("x_id").getAsString());
//
//        // Add the x_orgCna property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_orgCna"),
//                cveMetadata.get("x_orgCna").getAsString());
//
//        // Add the x_lastModifiedDate property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_lastModifiedDate"),
//                cveMetadata.get("x_lastModifiedDate").getAsString());
//
//        // Add the x_descriptionData property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_descriptionData"),
//                cveMetadata.get("x_descriptionData").getAsString());
//
//        // Add the x_titleData property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_titleData"),
//                cveMetadata.get("x_titleData").getAsString());
//
//        // Add the x_changeType property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_changeType"),
//                cveMetadata.get("x_changeType").getAsString());
//
//        // Add the x_publishedDate property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_publishedDate"),
//                cveMetadata.get("x_publishedDate").getAsString());
//
//        // Add the x_submitter property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_submitter"),
//                cveMetadata.get("x_submitter").getAsString());
//
//        // Add the x_references property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_references"),
//                cveMetadata.get("x_references").getAsString());
//
//        // Add the x_assignedToCveId property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_assignedToCveId"),
//                cveMetadata.get("x_assignedToCveId").getAsString());
//
//        // Add the x_assignedToCveNumberingAuthority property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_assignedToCveNumberingAuthority"),
//                cveMetadata.get("x_assignedToCveNumberingAuthority").getAsString());
//
//        // Add the x_vulnerableConfiguration property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_vulnerableConfiguration"),
//                cveMetadata.get("x_vulnerableConfiguration").getAsString());
//
//        // Add the x_status property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_status"),
//                cveMetadata.get("x_status").getAsString());
//
//        // Add the x_cnaComments property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_cnaComments"),
//                cveMetadata.get("x_cnaComments").getAsString());
//
//        // Add the x_changeDescription property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_changeDescription"),
//                cveMetadata.get("x_changeDescription").getAsString());
//
//        // Add the x_changeReason property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_changeReason"),
//                cveMetadata.get("x_changeReason").getAsString());
//
//        // Add the x_changeReviewer property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_changeReviewer"),
//                cveMetadata.get("x_changeReviewer").getAsString());
//
//        // Add the x_changeReviewDate property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_changeReviewDate"),
//                cveMetadata.get("x_changeReviewDate").getAsString());
//
//        // Add the x_changeReviewerComments property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_changeReviewerComments"),
//                cveMetadata.get("x_changeReviewerComments").getAsString());
//
//        // Add the x_changeReviewerId property to the CVE individual
//        cveIndividual.addProperty(ontologyModel.getProperty("http://birzeit.edu/cve_schema5_0#x_changeReviewerId"),
//                cveMetadata.get("x_changeReviewerId").getAsString());

        // Save the ontology model to a file
        try {
            FileOutputStream outputStream = new FileOutputStream("generated_cve_ontology.owl");
            ontologyModel.write(outputStream, "RDF/XML-ABBREV");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        System.out.println("Ontology creation completed.");
    }

    private static String removeSpecialChar(JsonArray platforms) {
        String s = "";
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
                .replaceAll(",", "_").replaceFirst("_","");
    }
}
