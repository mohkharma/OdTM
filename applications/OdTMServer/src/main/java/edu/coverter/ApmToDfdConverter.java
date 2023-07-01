package edu.coverter;

/**
 * Mohammed Kharma
 * 3/7/2023
 */

import ab.base.LManager;
import ab.base.PManager;
import ab.ext.ModelManager;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.gson.Gson;
import edu.coverter.apm.pojo.LinkDataArray;
import edu.coverter.apm.pojo.NodeDataArray;
import edu.coverter.dfd.pojo.*;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ApmToDfdConverter {
    public static void main(String[] args) {
        //JSON parser object to parse read file

        if (args.length == 0)
            System.exit(-1);

        LManager.init();

        PManager conf = new PManager();
        String inputFileName = null;
        String outputFileName = null;
        if (conf.init(args[0])) {
            ModelManager manager = new ModelManager();
            if (manager.init(conf)) {

                // class model IRI
                inputFileName = conf.get("4dtmTDFILE");
                outputFileName = conf.get("TDFILE");
            }
        }

        JSONParser jsonParser = new JSONParser();

        try (FileReader reader = new FileReader(inputFileName/*
                "./4dtm/APMToolOutoutExample.json"*/)) {
            //Read JSON file
            JSONObject obj = (JSONObject) jsonParser.parse(reader);

//https://stackoverflow.com/questions/29965764/how-to-parse-json-file-with-gson
            JSONArray linkDataObject = (JSONArray) ((JSONObject) obj.get("applicationMapData")
            ).get("linkDataArray");

            JSONArray nodeDataObject = (JSONArray) ((JSONObject) obj.get("applicationMapData")
            ).get("nodeDataArray");

            NodeDataArray[] nodeDataArray = new Gson().fromJson(nodeDataObject.toJSONString(),
                    NodeDataArray[].class);
            LinkDataArray[] linkDataArray = new Gson().fromJson(linkDataObject.toJSONString(),
                    LinkDataArray[].class);
            Dfd dfd = createDFD(nodeDataArray, linkDataArray);

            FileOutputStream fileOutputStream = null;
            try {
                fileOutputStream = new FileOutputStream(outputFileName);
                ObjectMapper myObjectMapper = new ObjectMapper();
                myObjectMapper.enable(SerializationFeature.INDENT_OUTPUT);
                myObjectMapper.writeValue(fileOutputStream, dfd);

//            fileOutputStream.write(jsonText.getBytes(StandardCharsets.UTF_8));
            } finally {
                if (fileOutputStream != null)
                    fileOutputStream.close();
            }

//            ApplicationMapData user = gson.fromJson(linkDataArray.toJSONString(),ApplicationMapData.class);
//            System.out.println(nodeDataArray[0].toString());
//            System.out.println(linkDataArray[0].toString());

            //Iterate over employee array
//            linkDataArray.forEach( emp -> parseEmployeeObject( (JSONObject) emp ) );

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }

    private static Dfd createDFD(NodeDataArray[] nodeDataArray, LinkDataArray[] linkDataArray) throws IOException {
        Dfd dfd = new Dfd();
        dfd.setSummary(generateDfdSummary());

        Detail detail = new Detail();
        Diagram diagram = new Diagram();
        diagram.setTitle("Diagram-1");
        diagram.setId(0);
        diagram.setDiagramType("STRIDE");
        diagram.setThumbnail("./public/content/images/thumbnail.stride.jpg");
        diagram.set$$hashKey("object:305"); //?????

        DiagramJson diagramJson = generateDiagramJson(nodeDataArray, linkDataArray);


        diagram.setDiagramJson(diagramJson);
        Size__1 size = new Size__1();
        size.setHeight(590);
        size.setWidth(844);
        diagram.setSize(size);

        ArrayList<Diagram> diagrams = new ArrayList<Diagram>();
        diagrams.add(diagram);
        detail.setDiagrams(diagrams);
        dfd.setDetail(detail);

        String jsonText = new Gson().toJson(dfd);
        System.out.println("--------------------------------------------------------");
        System.out.println("------------------DFD is generated----------------------");
        System.out.println("--------------------------------------------------------");
       return dfd;
    }

    private static DiagramJson generateDiagramJson(NodeDataArray[] nodeDataArray, LinkDataArray[] linkDataArray) {
        DiagramJson diagramJson = new DiagramJson();
        List<Cell> cells = new ArrayList<>();
        int z = 1;
        generateNodes(nodeDataArray, cells, z);
//        Cell actorCell;
//
//        for (int i = 0; i < cells.size(); i++) {
//            actorCell = cells.get(i);
//            if(actorCell.getType().equalsIgnoreCase("tm.Actor")){
//
//                for (int j = 0; j < cells.size(); j++) {
//                    Cell cell = cells.get(i);
//                    if(cell.getType().equalsIgnoreCase("tm.Actor")){
//
//                    }
//                }
//
//
//
//                break;
//            }
//        }

        generateFlows(linkDataArray, cells, z);

        diagramJson.setCells(cells);
        return diagramJson;
    }

    private static void generateFlows(LinkDataArray[] nodeDataArray, List<Cell> cells, int z) {

        for (LinkDataArray linkDataObject :
                nodeDataArray) {

            cells.add(generateRequestFlow(linkDataObject, z++, false));

            //generate the response arrow
            //todo check of sync or async operation to add the response arrow in case its sync operation
            cells.add(generateRequestFlow(linkDataObject, z++, true));
        }
    }

    private static Cell generateRequestFlow(LinkDataArray linkDataObject, Integer z, boolean isInversed) {
        Cell cell = new Cell();
        cell.setType("tm.Flow");
        Size size = new Size();
        size.setHeight(10);
        size.setWidth(10);
        cell.setSize(size);
        cell.setSmooth(true);

        cell.setId(linkDataObject.getKey() + isInversed);
        cell.setHasOpenThreats(false);

        Source source = new Source();
        Target target = new Target();
        Position position = new Position();
        List<Label> labels = new ArrayList<>();

        if (isInversed) {
            target.setId(linkDataObject.getFrom());
            source.setId(linkDataObject.getTo());
            position.setX(40);
            position.setY(60);
            Label label = new Label();
            Attrs__1 attrs__1 = new Attrs__1();
            Text__1 text__1 = new Text__1();
            text__1.setText("Response ");
            text__1.setFontSize("small");
            text__1.setFontWeight("400");
            attrs__1.setText(text__1);
            label.setAttrs(attrs__1);
            labels.add(label);
        } else {
            source.setId(linkDataObject.getFrom());
            target.setId(linkDataObject.getTo());
            position.setX(80);
            position.setY(120);
            Label label = new Label();
            Attrs__1 attrs__1 = new Attrs__1();
            Text__1 text__1 = new Text__1();
            text__1.setText("Request ");
            text__1.setFontSize("small");
            text__1.setFontWeight("400");
            attrs__1.setText(text__1);
            label.setAttrs(attrs__1);
            labels.add(label);
        }
        cell.setSource(source);
        cell.setPosition(position);
        cell.setLabels(labels);
//            cell.set(linkDataObject.getFilterTargetRpcList().get(0).getRpc().toString());


        cell.setTarget(target);

        Attrs attrs = new Attrs();
        MarkerTarget markerTarget = new MarkerTarget();
        markerTarget.setClass_("marker-target hasNoOpenThreats isInScope");
        attrs.setMarkerTarget(markerTarget);

        Connection connection = new Connection();
        connection.setClass_("connection hasNoOpenThreats isInScope");
        attrs.setConnection(connection);

        cell.setAttrs(attrs);


        cell.setAngle(0);
        cell.setZ(z);
        return cell;
    }

    private static void generateNodes(NodeDataArray[] nodeDataArray, List<Cell> cells, int z) {
        Cell cell;
/*
Read JSON file from APM tool
Parse JSON input and save in nodeDataArray

Loop element in nodeDataArray
    If element type equals "USER" Then
        Create DFD element of type External entity
    Else If element type equals "Application"  Then
        Create DFD element of type Process
    Else If element type equals "database"  Then
        Create DFD element of type Data Store
    End If

End Loop
 */

        for (NodeDataArray nodeDataObject :
                nodeDataArray) {
            if (nodeDataObject.getServiceType() == null) {
                continue;
            }
            cell = new Cell();
            /*  "serviceType": "USER",
        "serviceTypeCode": "2",*/
            Position position = new Position();
            position.setX(200 * z);
            position.setY(60);

            if (nodeDataObject.getServiceType().equalsIgnoreCase("USER")) {
                cell.setType("tm.Actor");
                Size size = new Size();
                size.setHeight(80);
                size.setWidth(160);
                cell.setSize(size);
                position.setY(250);
                cell.setDescription("class#RemoteUser;");
//                cell.set(false);//provide authintation
                //todo add trust boundary
                /*   "serviceType": "SPRING_BOOT",

        "serviceTypeCode": "1210",*/
            } else if (nodeDataObject.getServiceType().equalsIgnoreCase("SPRING_BOOT")) {
                cell.setType("tm.Process");
                Size size = new Size();
                size.setHeight(100);
                size.setWidth(100);
                cell.setSize(size);
                cell.setDescription("class#CloudApplication;"); //todo handle class#ExternalService
//                cell.setDescription("class#CloudApplication;\nrestriction#HasRestriction_Platform_Linux"); //todo handle class#ExternalService
//                cell.setDescription("class#CloudApplication;TECH#NGNIX;TECHVER#1.23.0;IPREF#10.122.22.10;restriction#HasRestriction_Platform_Linux"); //todo handle class#ExternalService
            }
            cell.setPosition(position);

            cell.setId(nodeDataObject.getKey());
            cell.setHasOpenThreats(false);

            Attrs attrs = new Attrs();
            ElementShape elementShape = new ElementShape();
            elementShape.setClass_("element-shape hasNoOpenThreats isInScope");
            attrs.setElementShape(elementShape);

            Text text = new Text();
            text.setText(nodeDataObject.getApplicationName());
            attrs.setText(text);

            ElementText elementText = new ElementText();
            elementText.setClass_("element-text hasNoOpenThreats isInScope");
            attrs.setElementText(elementText);

            cell.setAttrs(attrs);


            cell.setAngle(0);

            cell.setZ(z++);

            cells.add(cell);
        }
    }

    private static Summary generateDfdSummary() {
        Summary summary = new Summary();
        summary.setTitle("Data Flow Diagram - auto generated by converter");
        summary.setOwner("Mohammed Kharma");
        summary.setDescription("Generated by 4DTM Framework");
        return summary;
    }
//
//    private static void parseEmployeeObject(JSONObject employee) {
//        //Get employee object within list
//        JSONObject sourceInfoObject = (JSONObject) employee.get("sourceInfo");
//        JSONObject targetInfoObject = (JSONObject) employee.get("targetInfo");
//
//        String key = (String) employee.get("key");
//        String sourceInfoApplicationName = (String) sourceInfoObject.get("applicationName");
//        String sourceInfoServiceType = (String) sourceInfoObject.get("serviceType");
//
//        String targetInfoApplicationName = (String) targetInfoObject.get("applicationName");
//        String targetInfoServiceType = (String) targetInfoObject.get("serviceType");
//        System.out.println(sourceInfoApplicationName);
//        System.out.println(sourceInfoServiceType);
//        System.out.println(targetInfoApplicationName);
//        System.out.println(targetInfoServiceType);
//        System.out.println("---------------");
////
////        //Get employee last name
////        String lastName = (String) employeeObject.get("lastName");
////        System.out.println(lastName);
////
////        //Get employee website name
////        String website = (String) employeeObject.get("website");
////        System.out.println(website);
//    }
}
