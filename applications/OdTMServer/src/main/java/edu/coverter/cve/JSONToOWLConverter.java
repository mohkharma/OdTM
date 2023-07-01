package edu.coverter.cve;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import org.apache.jena.ontology.*;
import org.apache.jena.rdf.model.*;
import org.apache.jena.util.FileManager;
import org.apache.jena.vocabulary.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class JSONToOWLConverter {
    public static void main(String[] args) {
        // Read JSON file and convert it to a CVE object
        ObjectMapper mapper = new ObjectMapper();
        CVE cve = null;
        try {
            cve = mapper.readValue(/*new File("input.json")*/
                    CveV5Parser.json.replace("x_generator", "xgenerator"), CVE.class);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Create the OWL model
        OntModel ontologyModel = ModelFactory.createOntologyModel(OntModelSpec.OWL_DL_MEM);

        // Set the namespace prefixes
        String cveSchemaNS = "http://example.org/cve-schema#";
        ontologyModel.setNsPrefix("cve-schema", cveSchemaNS);

        // Create the resource for the CVE record
        Resource cveResource = ontologyModel.createResource(cveSchemaNS + cve.getCveMetadata().getCveId());
        cveResource.addProperty(RDF.type, ontologyModel.getResource(cveSchemaNS + "CVE_RECORD"));

        // Populate the CVE resource with properties from the CVE object
        cveResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "dataType"), cve.getDataType());
        cveResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "dataVersion"), cve.getDataVersion());

        // Create and add the cveMetadata resource
        Resource cveMetadataResource = ontologyModel.createResource(cveSchemaNS + "CVEMetadata-" + cve.getCveMetadata().getCveId());
        cveResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "cveMetadata"), cveMetadataResource);
        // Set the properties of the cveMetadata resource
        cveMetadataResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "cveId"), cve.getCveMetadata().getCveId());
        cveMetadataResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "assignerOrgId"), cve.getCveMetadata().getAssignerOrgId());
        cveMetadataResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "state"), cve.getCveMetadata().getState());
        cveMetadataResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "assignerShortName"), cve.getCveMetadata().getAssignerShortName());
        cveMetadataResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "dateReserved"), cve.getCveMetadata().getDateReserved());
        cveMetadataResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "datePublished"), cve.getCveMetadata().getDatePublished());
        // ... set other properties of cveMetadata

        // Create and add the containers resource
        Resource containersResource = ontologyModel.createResource(cveSchemaNS + "containers-" + cve.getCveMetadata().getCveId());
        cveResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "containers"), containersResource);

        // Create and add the cna resource
        Resource cnaResource = ontologyModel.createResource(cveSchemaNS + "cna-" + cve.getCveMetadata().getCveId());
        containersResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "cna"), cnaResource);

        // Create and add the affected resources
        for (Affected affected : cve.getContainers().getCna().getAffected()) {
            Resource affectedResource = ontologyModel.createResource(cveSchemaNS + "affected-" + cve.getCveMetadata().getCveId());
            cnaResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "affected"), affectedResource);
            affectedResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "defaultStatus"), affected.getDefaultStatus());
            affectedResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "product"), affected.getProduct());
            affectedResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "vendor"), affected.getVendor());

//            // Create and add the platforms
//            for (String platform : affected.getPlatforms()) {
//                affectedResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "platforms"), platform);
//            }

            // Create and add the versions
//            for (Version version : affected.getVersions()) {
//                Resource versionResource = ontologyModel.createResource(cveSchemaNS + "version-" + version.getVersion());
//                affectedResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "versions"), versionResource);
//                versionResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "status"), version.getStatus());
//                versionResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "version"), version.getVersion());
//                versionResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "versionType"), version.getVersionType());

                // Create and add the changes
//                for (Change change : version.getChanges()) {
//                    Resource changeResource = ontologyModel.createResource(cveSchemaNS + "change-" + version.getVersion() + "-" + change.getAt());
//                    versionResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "changes"), changeResource);
//                    changeResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "at"), change.getAt());
//                    changeResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "status"), change.getStatus());
//                }
//            }
        }

        // Create and add the credits resources
//        for (Credit credit : cve.getContainers().getCna().getCredits()) {
//            Resource creditResource = ontologyModel.createResource(cveSchemaNS + "credit-" + cve.getCveMetadata().getCveId());
//            cnaResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "credits"), creditResource);
//            creditResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "lang"), credit.getLang());
//            creditResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "type"), credit.getType());
//            creditResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "user"), credit.getUser());
//            creditResource.addProperty(ontologyModel.getProperty(cveSchemaNS + "value"), credit.getValue());
//        }

        // ... add other properties and relations based on the CVE class structure

        // Save the ontology model to an OWL file
        try (OutputStream output = new FileOutputStream("output.owl")) {
            ontologyModel.write(output, "RDF/XML");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
