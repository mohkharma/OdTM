package edu.coverter.cve;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;

import java.io.*;

public class JsonToOWLConverter2 {

    public static void main(String[] args) {
        String jsonFilePath = "C:\\M.kharma_data\\PhD\\03-Semester-2022\\Threat-modeling\\OdTM-mkharma\\cveExample.csv";

        Model ontologyModel = ModelFactory.createDefaultModel();

        try  {
            Reader inputStream = new FileReader(jsonFilePath);
            JsonObject jsonObject = JsonParser.parseReader(inputStream).getAsJsonObject();

            // Create and add the root resource
            Resource rootResource = ontologyModel.createResource("http://example.org/cve#CVE_Record");
            ontologyModel.add(rootResource, ontologyModel.createProperty("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                    ontologyModel.createResource("http://www.w3.org/2002/07/owl#Class"));

            // Process the JSON data and add individuals and properties to the ontology model
            processJsonData(jsonObject, ontologyModel, rootResource);

            // Save the ontology model to a file in OWL format
            ontologyModel.write(System.out, "RDF/XML-ABBREV");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void processJsonData(JsonObject jsonObject, Model ontologyModel, Resource parentResource) {
        for (String key : jsonObject.keySet()) {
            if (jsonObject.get(key).isJsonObject()) {
                // Create a new resource for the nested object
                Resource childResource = ontologyModel.createResource("http://example.org/cve#" + key);
                ontologyModel.add(childResource, ontologyModel.createProperty("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                        ontologyModel.createResource("http://www.w3.org/2002/07/owl#Class"));

                // Add a property to connect the parent and child resources
                Property property = ontologyModel.createProperty("http://example.org/cve#" + key);
                ontologyModel.add(parentResource, property, childResource);

                // Recursively process the nested object
                processJsonData(jsonObject.getAsJsonObject(key), ontologyModel, childResource);
            } else {
                // Create a new property for the JSON key-value pair
                Property property = ontologyModel.createProperty("http://example.org/cve#" + key);

                // Add the property and value to the parent resource
                String value = jsonObject.get(key).getAsString();
                ontologyModel.add(parentResource, property, value);
            }
        }
    }
}

