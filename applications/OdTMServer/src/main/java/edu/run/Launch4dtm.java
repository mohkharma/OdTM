package edu.run;

import ab.run.consoleApplication;
import edu.coverter.ApmToDfdConverter;

/**
 * Mohammed Kharma
 * 3/9/2023
 *To run the class
 * ~\OdTM-mkharma\applications\OdTMServer> \
mvn -e exec:java -q -D"exec.mainClass"="ab.run.consoleApplication" -D"exec.args"="./4dtm/cases/server_acctp1.properties"
mvn -e exec:java -q -D"exec.mainClass"="edu.run.Launch4dtm" -D"exec.args"="./4dtm/cases/server_acctp1.properties"
 */
//       <!--  Added by mkhrama
//       https://www.digitalocean.com/community/tutorials/exec-maven-plugin-run-java-programs-maven-build
//     To run
//       mvn compile
//       mvn exec:java
// mvn -e exec:java -q -D"exec.mainClass"="edu.run.Launch4dtm" -D"exec.args"="./4dtm/cases/server_acctp2.properties"
//               -->
public class Launch4dtm {

    public static void main(String[] args) {
//        ApmToDfdConverter.main(args);
        new consoleApplication().main(args);
//        consoleApplication.main(new String[]{"C:/M.kharma_data/PhD/03-Semester-2022/Threat-modeling/OdTM-mkharma/applications/OdTMServer/4dtm/cases/server_case_template.properties"});
    }
}
