package ab.ext;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;

import org.semanticweb.owlapi.model.*;
import uk.ac.manchester.cs.owl.owlapi.*;
import org.semanticweb.HermiT.Reasoner;
import org.semanticweb.owlapi.reasoner.*;
import org.semanticweb.owlapi.apibinding.*;
import org.semanticweb.owlapi.util.*;
import org.semanticweb.owlapi.formats.*;
import org.semanticweb.owlapi.reasoner.structural.*;
import org.semanticweb.owlapi.search.EntitySearcher;
import org.semanticweb.owlapi.model.parameters.*;
import org.semanticweb.owlapi.model.providers.*;
import org.semanticweb.owlapi.util.mansyntax.*;
import org.semanticweb.owlapi.expression.*;
import java.io.*;
import java.util.*;
import java.util.stream.*;
import java.time.Duration;
import java.time.Instant;
import java.util.logging.*;
import java.util.function.*;
import ab.base.*;

// here it is
public class ThreatModeller extends OManager {
   private static final Logger LOGGER = Logger.getLogger(LManager.class.getName());
   
   protected ArrayList<OWLOntology> models;
   protected OWLOntology baseModel;    // the first model
   protected OWLOntology domainModel;  // the second one
   protected OWLOntology classModel;   // ???
   protected OWLOntology workModel;    // and abox (i.e. diagram) is here
   protected O bmodel;                 // base threat model
   protected O dmodel;                 // domain specific threat model
   protected O cmodel;                 // class model
   protected O model;                  // processor for workModel, init it with workModel
   
   protected String domainModelIRI;    // will be applied to abox as import
   protected String classModelIRI;     // used to recognize extra classes from domain specific model
   
   protected static String DataFlowClass = "http://www.grsu.by/net/OdTMBaseThreatModel#DataFlow";
   protected static String TargetClass = "http://www.grsu.by/net/OdTMBaseThreatModel#Target";
   protected static String ProcessClass = "http://www.grsu.by/net/OdTMBaseThreatModel#Process";
   protected static String ExternalInteractorClass = "http://www.grsu.by/net/OdTMBaseThreatModel#ExternalInteractor";
   protected static String DataStoreClass = "http://www.grsu.by/net/OdTMBaseThreatModel#DataStore";
   protected static String ClassifiedClass = "http://www.grsu.by/net/OdTMBaseThreatModel#Classified";
   protected static String ClassifiedIsEdgeClass = "http://www.grsu.by/net/OdTMBaseThreatModel#ClassifiedIsEdge";
   protected static String ClassifiedHasEdgeClass = "http://www.grsu.by/net/OdTMBaseThreatModel#ClassifiedHasEdge";
   protected static String HasSourceProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#hasSource";
   protected static String HasTargetProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#hasTarget";
   protected static String HasEdgeProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#hasEdge";
   protected static String IsSourceOfProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#isSourceOf";
   protected static String IsTargetOfProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#isTargetOf";
   protected static String IsEdgeOfProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#isEdgeOf";   
   protected static String IsAffectedByProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#isAffectedBy";
   protected static String IsAffectedByTargetsProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#isAffectedByTargets";
   protected static String IsAffectedByTargetProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#isAffectedByTarget";
   protected static String IsAffectedBySourceProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#isAffectedBySource";   
   protected static String SuggestsProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#suggests";
   protected static String SuggestsThreatCategoryProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#suggestsThreatCategory";
   protected static String SuggestsThreatProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#suggestsThreat"; 
   protected static String HasIDProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#hasID"; 
   protected static String HasTextProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#hasText"; 
   protected static String HasTitleProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#hasTitle";
   protected static String HasDescriptionProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#hasDescription";
   protected static String HasSeverityProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#hasSeverity";
   protected static String LabelsSTRIDE = "http://www.grsu.by/net/OdTMBaseThreatModel#labelsSTRIDE";
   protected static String HasRestrictionsClass = "http://www.grsu.by/net/OdTMBaseThreatModel#HasRestrictions";
   protected static String ThreatRestrictionClass = "http://www.grsu.by/net/OdTMBaseThreatModel#ThreatRestriction";
   protected static String SatisfiesProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#satisfiesThreatRestriction";

   protected static String refToTacticProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#refToTactic";
   protected static String refToATTCKProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#refToATTCK";
   protected static String refToCAPECProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#refToCAPEC";
   protected static String refToCWEProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#refToCWE";
   protected static String refToCVEProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#refToCVE";
   protected static String isRefToATTCKProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#isRefToATTCK";
   protected static String isRefToCAPECProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#isRefToCAPEC";
   protected static String isRefToCWEProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#isRefToCWE";
   protected static String refToCAPECreasonedProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#refToCAPECreasoned";
   protected static String refToCWEreasonedProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#refToCWEreasoned";
   protected static String refToCVEreasonedProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#refToCVEreasoned";
   protected static String refToEnumProperty = "http://www.grsu.by/net/OdTMBaseThreatModel#refToEnum";   
   
   // !!! legacy
   // init it with base model & domain model before use 
   public boolean init (OWLOntology _baseModel, OWLOntology _domainModel){

      if (_baseModel !=null){
         baseModel = copyOntology(_baseModel);
         if (baseModel == null){
            LOGGER.severe ("unable to copy base model");      
            return false;
         }
         bmodel = O.create(baseModel);
         LOGGER.info("base model: "+ getBaseModelIRI());
      } 
      
      // legacy approach, when the base model is used as a domain model 
      domainModel = copyOntology(_domainModel);
      if (domainModel == null){
         LOGGER.severe ("unable to copy domain model");      
         return false;
      }
      
      dmodel = O.create(domainModel);
      domainModelIRI = getDomainModelIRI();
      LOGGER.info("domain model: "+ domainModelIRI);
            
      return true;
   } 

  // init modeller with 
  //   - the base threat model
  //   - list of extra models
  //   - IRI of the domain threat model (can be null)
  //   - IRI of the class model (can be null)
  public boolean init (OWLOntology _baseModel, ArrayList<OWLOntology> _models, String _domainModelIRI, String _classModelIRI){

      // init the base model
      if (_baseModel !=null){
         baseModel = copyOntology(_baseModel);
         if (baseModel == null){
            LOGGER.severe ("unable to copy base model");      
            return false;
         }
         bmodel = O.create(baseModel);
         LOGGER.info("base model: "+ getBaseModelIRI());
      } else {
         LOGGER.severe ("base model is null");      
         return false;
      }

      // init extra models
      models = new ArrayList<OWLOntology>();         
      for (int i=0;i<_models.size();i++){
         OWLOntology m = copyOntology(_models.get(i));
         models.add(m);
      }
      
      if (_domainModelIRI !=null){
         // init domain model   
         domainModel = getOntologyByIRI(_domainModelIRI);
         if (domainModel == null){
            LOGGER.severe ("no domain model in the list of models");      
            return false;
         }
         dmodel = O.create(domainModel);
         domainModelIRI = _domainModelIRI;
         LOGGER.info("domain model: "+ domainModelIRI);
      } else{
         // use the base model
         domainModel = baseModel;
         dmodel = bmodel;
         domainModelIRI = getBaseModelIRI();
         LOGGER.info("use the base model as a domain model: "+ domainModelIRI);
      }
      
      // init class model
      if (_classModelIRI !=null){
         classModel = getOntologyByIRI(_classModelIRI);
         if (classModel == null){
            LOGGER.severe ("no class model in the list of models");      
            return false;
         }
        cmodel = O.create(classModel);
        classModelIRI = _classModelIRI;
        LOGGER.info("class model: "+ classModelIRI);
      }


      return true;
   } 


   public String getBaseModelIRI(){
      return getIRI(baseModel).toString();
   }
   
   public String getDomainModelIRI(){
      return getIRI(domainModel).toString();
   }
   

    public void fillWorkModel(){
       model.fill();
    }
   
    public void flushModel(){
       model.flush();
    }

    public boolean isItFromBaseModel(IRI iri){
       if (bmodel!=null) {
          if (bmodel.hasDefaultPrefix(iri)) return true;
       }
       return false;      
    }


    // to perform an operation with an object (i.e. EntitySearch related methods in O)  
    // we need to know where this object is (in base or domain model)
    protected O getModelByIRI(IRI iri){
       if (bmodel!=null) {
          if (bmodel.hasDefaultPrefix(iri)) return bmodel;
       }
       if (dmodel.hasDefaultPrefix(iri)) return dmodel;
       // ignoring owl:thing
       if (iri.toString().equals("http://www.w3.org/2002/07/owl#Thing")) return null;
       // failed
       LOGGER.severe("could not found model for "+ iri.toString());
       return null;
    }

    protected O getModelByIRI1(IRI iri){       
       // is it dmodel?
       if (dmodel != null){
          if (dmodel.hasDefaultPrefix(iri)) return dmodel;
       }
       // is it cmodel?
       if (cmodel != null){
          if (cmodel.hasDefaultPrefix(iri)) return cmodel;
       }
       // is it bmodel?
       if (bmodel!=null) {
          if (bmodel.hasDefaultPrefix(iri)) return bmodel;
       }
       // ignoring owl:thing
       if (iri.toString().equals("http://www.w3.org/2002/07/owl#Thing")) return null;
       
       //what is it?
       String pr = iri.getNamespace();
       String pr1 = pr.substring(0, pr.length() - 1);
       OWLOntology tmp = getOntologyByIRI(pr1);
       if (tmp!=null) return O.create(tmp);
       
       // failed
       LOGGER.severe("could not found model for "+ iri.toString());
       return null;
    }


    // get model by its iri as OWLOntology
    public OWLOntology getOntologyByIRI(String iri){ 
       for (int i=0;i<models.size();i++){
         OWLOntology tmp = models.get(i);
         if (iri.equals(tmp.getOntologyID().getOntologyIRI().get().toString())) return tmp;
       }      
       LOGGER.severe ("no such model " + iri);      
       return null;
    }    
 
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Threat Modeller & JSON 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// 
 
   // convert TD objects to ontology's objects
   public IRI convertJSONtype(String type){
      if (type.equals("tm.Process")) return IRI.create(ProcessClass);
      if (type.equals("tm.Actor")) return IRI.create(ExternalInteractorClass);  
      if (type.equals("tm.Store")) return IRI.create(DataStoreClass);
      if (type.equals("tm.Flow")) return IRI.create(DataFlowClass);
      return null;
   }
   
   // before use of convertJSONclass
   public boolean addClassModel(String in){
      if (in!=null){
         classModelIRI = in;
      }
      return true;
   }
   
   // parse the "class#CloudApplication" like entities
   public IRI convertJSONclass(String in){
      if (in !=null){
         String[] args = in.split("#");
         if (args.length ==2){
            String prefix = args[0];
            String name = args[1];
            if (prefix.equals("class")){
               String res = classModelIRI+"#"+name;
               return IRI.create(res);
            }
         }
      }
      return null;
   }

   // parse the "class#CloudApplication" & "restriction#HasRestriction_SomeRestriction" like entities
   // and apply needed axioms
   public boolean applyJSONclasses(String in, IRI itemIRI){
      if (in !=null){
         in = in.replace("\n", "");
         String[] args = in.split(";");
         for (int i=0; i<args.length; i++){
            System.out.println("--------------------------------args[i]------------------------" + args[i]);

            String[] args2 = args[i].split("#");
            if (args2.length ==2){
               String prefix = args2[0];
               String name = args2[1];
               if (prefix.equals("class") || prefix.equals("restriction")){
                  String res = classModelIRI+"#"+name;
                  // apply class to instance
                  model.addAxiom(model.getClassAssertionAxiom(IRI.create(res), itemIRI));
//                  model.flush();
                  // !!! item belongs to the 'HasRestrictions'
                  if(prefix.equals("restriction")) model.addAxiom(model.getClassAssertionAxiom(IRI.create(HasRestrictionsClass), itemIRI));

                  //            //todo mkharma
//                  // get cves with the 'refToCVEreasoned' property
//                  String descriptionCVE = "";
//                  List<OWLNamedIndividual> cves = model.getReasonerObjectPropertyValues(tmp.getIRI(),IRI.create(refToCVEreasonedProperty)).sorted().collect(Collectors.toList());
//                  if (cves !=null){
//                     for (Iterator<OWLNamedIndividual> iterator5 = cves.stream().iterator(); iterator5.hasNext(); ){
//                        OWLNamedIndividual cve =  (OWLNamedIndividual)iterator5.next();
//                        String cveComment = getModelByIRI1(cve.getIRI()).getSeacherComment(cve);
//                        if (cveComment != null) descriptionCVE = descriptionCVE+"\n"+cveComment+"; ";
//                     }
//                     if (!descriptionCVE.equals("")) description = description + descriptionCVE;
//                  }
//            ///------------
//                  String cveID = vuln.CVEs.get(ii);
//                  IRI cveIRI = IRI.create(dModel.getDefaultPrefix()+ cveID);
//                  dModel.addAxiom(dModel.getClassAssertionAxiom(IRI.create(CVEClass),cveIRI));
//                  dModel.addAxiom(dModel.getObjectPropertyAssertionAxiom(IRI.create(refToCVEProperty),cweIRI,cveIRI));
//                  // label
//                  dModel.addAxiom(dModel.getIndividualAnnotation(cveIRI, cveID, "en"));





               }
               if (prefix.equals("enum")){
                  IRI enumIRI = IRI.create(classModelIRI+"#"+name);
                  // like HasEnum_CWE-284
                  IRI searchIRI = IRI.create(model.getDefaultPrefix()+"HasEnum_"+name);
                  // HasEnum_CWE-284 = refToEnum value CWE-284
                  model.addAxiom(model.getDefinedClassValue(searchIRI, IRI.create(refToEnumProperty), enumIRI));
                  model.flush();
                  // threats are individuals of HasEnum_CWE-284
                  List<OWLNamedIndividual> threats = model.getReasonerInstances(searchIRI).sorted().collect(Collectors.toList());
                  for (Iterator<OWLNamedIndividual> iterator = threats.stream().iterator(); iterator.hasNext(); ){
                      OWLNamedIndividual  threat = (OWLNamedIndividual)iterator.next();
                      // <itemIRI> isAffectedBy threat
                      model.addAxiom(model.getObjectPropertyAssertionAxiom(IRI.create(IsAffectedByProperty),itemIRI,threat.getIRI()));
                  }
 
               }
            }            
         }
         return true;
       }
       return false;
   }


    public ArrayList<OWLNamedIndividual> findAggressorsJSON(IRI targetIRI, IRI threatIRI){
       List<OWLNamedIndividual> flows = model.getReasonerObjectPropertyValues(targetIRI,IRI.create(IsEdgeOfProperty)).collect(Collectors.toList());
       if (flows == null){
          LOGGER.severe("no flows");
          return null;
       }
       ArrayList<OWLNamedIndividual> res = new ArrayList<OWLNamedIndividual>();
       for (Iterator<OWLNamedIndividual> iterator = flows.stream().iterator(); iterator.hasNext(); ){
           OWLNamedIndividual flow = (OWLNamedIndividual)iterator.next();
           String prop;
           OWLAxiom ax1 = model.getObjectPropertyAssertionAxiom(IRI.create(HasSourceProperty), flow.getIRI(), targetIRI);
           if (model.containsAxiom1(ax1)){
              prop = IsAffectedBySourceProperty;
           } else{
              prop = IsAffectedByTargetProperty;
           }
           OWLAxiom ax = model.getObjectPropertyAssertionAxiom(IRI.create(prop), flow.getIRI(), threatIRI);
           if (model.containsAxiom1(ax)){
               res.add(flow);
           }
       }       
       return res;
    }

   
   // takes a JSonNode that represents a diagram and creates a work model.
   // Caution! A poor example of Jackson's use. Use ObjectMapper instead??? 
   public boolean createWorkModelFromJSON(JsonNode diagram){
      // create empty model with the domain model import
      workModel = create("http://tmp.local");
      addImportDeclaration(workModel,getDomainModelIRI());
      model = O.create(workModel);
      if (model == null) {
         LOGGER.severe ("unable to create ontology");      
         return false;
      }
            
      // get all the items of the diagram
      JsonNode cells = diagram.path("diagramJson").path("cells");
      Iterator<JsonNode> itr1 = cells.elements();
      while (itr1.hasNext()) {
         // consider an item
         JsonNode cell = itr1.next(); 

         // get item's ID
         String cellID = cell.path("id").textValue();
         if (cellID == null){
            LOGGER.severe("could not find id ");
            return false;               
         }
         // generate name
         IRI nameIRI = IRI.create(model.getDefaultPrefix()+O.safeIRI(cellID));
         // add ID
         model.addAxiom(model.getIndividualDataProperty(nameIRI,IRI.create(HasIDProperty),cellID));
         
         // get type        
         String cellType = cell.path("type").textValue();
         IRI typeIRI = convertJSONtype(cellType);
         if (typeIRI == null){
            LOGGER.severe("could not find the type "+ cellType);
            return false;   
         }
         // add type
         model.addAxiom(model.getClassAssertionAxiom(typeIRI, nameIRI));

         // get classes & restrictions
         // it is in the 'descripion' tag and 
         //    has the 'class#' (both flows and targets) 
         //    & 'restriction#' prefixes (for targets)
         // like:
         //    class#SomeClass;
         //    restriction#SomeRestrictionClass
         String cellClass = cell.path("description").textValue();
         applyJSONclasses(cellClass,nameIRI);

         // get & add text
         String cellText = null;
         if (cellType.equals("tm.Flow")){
            JsonNode labels = cell.path("labels");
            Iterator<JsonNode> itr2 = labels.elements();
            if (itr2.hasNext()) cellText=((JsonNode)itr2.next()).path("attrs").path("text").path("text").textValue();
         } else{
            cellText = cell.path("attrs").path("text").path("text").textValue();
         }
         if (cellText != null) {
            model.addAxiom(model.getIndividualDataProperty(nameIRI,IRI.create(HasTextProperty),cellText));
         }

         // for flows add source & target edges
         if (cellType.equals("tm.Flow") ){
             String sourceID = cell.path("source").path("id").textValue();
             if (sourceID !=null) {
                 IRI sourceIRI = IRI.create(model.getDefaultPrefix()+O.safeIRI(sourceID));
                 model.addAxiom(model.getObjectPropertyAssertionAxiom(IRI.create(HasSourceProperty), nameIRI, sourceIRI));
             }
             String targetID = cell.path("target").path("id").textValue();
             if (targetID !=null) {
                 IRI targetIRI = IRI.create(model.getDefaultPrefix()+O.safeIRI(targetID));
                 model.addAxiom(model.getObjectPropertyAssertionAxiom(IRI.create(HasTargetProperty), nameIRI, targetIRI));
             }
         }
                  
         //       
                  
      }  
      
      return true;
   }
 
   // applies reasoning results a json diagram
   // !!! a bad primer of Jackson's use...
   public boolean applyAxiomsToJSON(JsonNode diagram){
      JsonNode cells = diagram.path("diagramJson").path("cells");
      Iterator<JsonNode> itr1 = cells.elements();
      while (itr1.hasNext()) {
         // consider an item, i.e. cell
         JsonNode cell = itr1.next(); 
         
         // get ID
         String cellID = cell.path("id").textValue();
         if (cellID == null){
            LOGGER.severe("could not find id ");
            return false;               
         }   
         // get name
         IRI nameIRI = IRI.create(model.getDefaultPrefix()+O.safeIRI(cellID)); //like: http://tmp.local#x5cf5e6cedashaa73dash4316dashae70dash6d6268a91b0e
         
         // get type        
         String cellType = cell.path("type").textValue();
         IRI typeIRI = convertJSONtype(cellType);
         if (typeIRI == null){
            LOGGER.severe("could not find the type "+ cellType);
            return false;   
         }   
         
         // reason the model  
         model.flush();  

         // if component belongs to the 'HasRestrictions' class, restrictions exist of its applicability
         // threat should be checked, if they satisfy the restrictions
         boolean hasRestrictions = model.isReasonerIndividualBelongsToClass(nameIRI,IRI.create(HasRestrictionsClass));

         // get threats from the ontological model
         List<OWLNamedIndividual> threats = model.getReasonerObjectPropertyValues(nameIRI,IRI.create(IsAffectedByProperty)).sorted().collect(Collectors.toList());
         if (threats.size() !=0) {
            ((ObjectNode)cell).put("hasOpenThreats", "true"); // put the 'hasOpenThreats' tag
            ArrayNode nodes = JsonNodeFactory.instance.arrayNode(); // generate an array
            // process each threat
            for (Iterator<OWLNamedIndividual> iterator4 = threats.stream().iterator(); iterator4.hasNext(); ){
               OWLNamedIndividual tmp = (OWLNamedIndividual)iterator4.next(); // instance of the threat
               O modelOfThreat = getModelByIRI1(tmp.getIRI()); // model from what the threat comes (base or domain) 
               String ruleId = tmp.getIRI().toString(); // get rule ID
               String shortIRI = O.getShortIRI(tmp);
               
               // skip if threat does not satisfy component and not from base model
               if (hasRestrictions && !isItFromBaseModel(tmp.getIRI()) ) {
                  OWLAxiom ax = model.getObjectPropertyAssertionAxiom(IRI.create(SatisfiesProperty),nameIRI, tmp.getIRI());
                  if (!model.containsAxiom1(ax)) continue;
               }
   
               // trying to get title from the 'hasTitle' property...
               String title = modelOfThreat.getSearcherDataPropertyValue(tmp.getIRI(), IRI.create(HasTitleProperty)); // get title
               if (title == null) {
                  // ... or from label
                  title = modelOfThreat.getSeacherLabel(tmp);
               }
               // trying to get a basic description from the 'hasDescription' property ...
               String description = modelOfThreat.getSearcherDataPropertyValue(tmp.getIRI(), IRI.create(HasDescriptionProperty)); // get description
               if (description == null){
                  // ... or from comment
                  description = modelOfThreat.getSeacherComment(tmp);
                  if (description == null) description = shortIRI;
               }
               description = description+";";
               
               // get type (!!! only one at the moment)  <threat> labelsSTRIDE <some STRIDE>
               OWLNamedIndividual typeInstance = model.getObjectPropertyValueFromOntology(tmp.getIRI(),IRI.create(LabelsSTRIDE),bmodel.getIRI());
               String type =null;
               if (typeInstance!=null) type = getModelByIRI1(typeInstance.getIRI()).getSearcherDataPropertyValue(typeInstance.getIRI(), IRI.create(HasTitleProperty));   

               // get tactics with the 'refToTactic' property
               String descriptionTactic = "";
               List<OWLNamedIndividual> tactics = model.getReasonerObjectPropertyValues(tmp.getIRI(),IRI.create(refToTacticProperty)).sorted().collect(Collectors.toList());
               if (tactics !=null){
                  for (Iterator<OWLNamedIndividual> iterator5 = tactics.stream().iterator(); iterator5.hasNext(); ){
                     OWLNamedIndividual tactic =  (OWLNamedIndividual)iterator5.next();
                     String tacticComment = getModelByIRI1(tactic.getIRI()).getSeacherComment(tactic);
                     if (tacticComment != null) descriptionTactic = descriptionTactic+"\n" +tacticComment+"; ";
                  }
                  if (!descriptionTactic.equals("")) description = description + descriptionTactic;
               }

    
               // get capecs with the 'refToCAPECreasoned' property
               String descriptionCAPEC = "";
               List<OWLNamedIndividual> capecs = model.getReasonerObjectPropertyValues(tmp.getIRI(),IRI.create(refToCAPECreasonedProperty)).sorted().collect(Collectors.toList());
               if (capecs !=null){
                  for (Iterator<OWLNamedIndividual> iterator5 = capecs.stream().iterator(); iterator5.hasNext(); ){
                     OWLNamedIndividual capec =  (OWLNamedIndividual)iterator5.next();
                     String capecComment = getModelByIRI1(capec.getIRI()).getSeacherComment(capec);
                     if (capecComment != null) descriptionCAPEC = descriptionCAPEC+"\n" +capecComment+"; ";
                  }
                  if (!descriptionCAPEC.equals("")) description = description + descriptionCAPEC;
               }
         
               // get cwes with the 'refToCWEreasoned' property
               String descriptionCWE = "";
               List<OWLNamedIndividual> cwes = model.getReasonerObjectPropertyValues(tmp.getIRI(),IRI.create(refToCWEreasonedProperty)).sorted().collect(Collectors.toList());
               if (cwes !=null){
                  for (Iterator<OWLNamedIndividual> iterator5 = cwes.stream().iterator(); iterator5.hasNext(); ){
                     OWLNamedIndividual cwe =  (OWLNamedIndividual)iterator5.next();
                     String cweComment = getModelByIRI1(cwe.getIRI()).getSeacherComment(cwe);
                     if (cweComment != null) descriptionCWE = descriptionCWE+"\n"+cweComment+"; ";
                  }
                  if (!descriptionCWE.equals("")) description = description + descriptionCWE;
               }
         
               // get cves with the 'refToCVEreasoned' property
               String descriptionCVE = "";
               List<OWLNamedIndividual> cves = model.getReasonerObjectPropertyValues(tmp.getIRI(),IRI.create(refToCVEreasonedProperty)).sorted().collect(Collectors.toList());
               if (cves !=null){
                  for (Iterator<OWLNamedIndividual> iterator5 = cves.stream().iterator(); iterator5.hasNext(); ){
                     OWLNamedIndividual cve =  (OWLNamedIndividual)iterator5.next();
                     String cveComment = getModelByIRI1(cve.getIRI()).getSeacherComment(cve);
                     if (cveComment != null) descriptionCVE = descriptionCVE+"\n"+cveComment+"; ";
                  }
                  if (!descriptionCVE.equals("")) description = description + descriptionCVE;
               }

         
               String reasonText ="";
               // if it isn't a dataflow
               if (!cellType.equals("tm.Flow")){
                  // get list of reasons (i.e. flows) 
                  List<OWLNamedIndividual> flows = findAggressorsJSON(nameIRI,tmp.getIRI());
                  
                  if (flows.size() !=0){
                     for (Iterator<OWLNamedIndividual> iterator = flows.stream().iterator(); iterator.hasNext(); ){
                        OWLNamedIndividual flow = (OWLNamedIndividual)iterator.next();
                        reasonText = reasonText +model.getSearcherDataPropertyValue(flow.getIRI(), IRI.create(HasTextProperty))+ "; ";
                     } 
                  } else {
                     reasonText = "by existence";   
                  }
                  
                  // no flows
                  ObjectNode threatNode = nodes.addObject(); // add a JSON node
                  // add ruleId
                  threatNode.put("ruleId", ruleId);
                  // add title
                  if (title !=null) threatNode.put("title", title);
                  else threatNode.put("title", shortIRI);
                  // add description
                  threatNode.put("description", description+"\nreason: "+reasonText );
                  // add status
                  threatNode.put("status", "Open");
                  // add severity (Medium at the moment)
                  threatNode.put("severity", "Medium");
                  // add type 
                  if (type != null) threatNode.put("type", type);                  
                  
                  
               }  else {
                  // copy-past
                  ObjectNode threatNode = nodes.addObject(); // add a JSON node
                  // add ruleId
                  threatNode.put("ruleId", ruleId);
                  // add title
                  if (title !=null) threatNode.put("title", title);
                  else threatNode.put("title", shortIRI);
                  // add description
                  threatNode.put("description", description);
                  // add status
                  threatNode.put("status", "Open");
                  // add severity (Medium at the moment)
                  threatNode.put("severity", "Medium");
                  // add type 
                  if (type != null) threatNode.put("type", type);
                  
               }       
               
                

               // standard fields
               // {
               //   "ruleId": "b2a6d40d-d3f8-4750-8e4d-c02cc84b13dc",
               //   "title": "Generic spoofing threat",
               //   "type": "Spoofing",
               //   "status": "Open",
               //   "severity": "Medium",
               //   "description": "A generic spoofing threat",
               //   "$$hashKey": "object:59"
               // }

            }
            ((ObjectNode)cell).set("threats",nodes); // apply nodes to cell (i.e. item)
            
                        
         }

      }      
      //saveToFile(model.get(),"cases/model.owl");
      return true;
   }
 
 
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AIEd & simple analysis of axioms
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////        

   public boolean createWorkModelFromFile(String filename){
      // get model configuration from file
      ArrayList<String> cc = readFileToArrayList(filename);
      if (cc == null){
         LOGGER.severe ("unable to get work model from " + filename);      
         return false;
      }

      // create empty model with the domain model import
      workModel = create("http://tmp.local");
      addImportDeclaration(workModel,getDomainModelIRI());
      model = O.create(workModel);
      if (model == null) {
         LOGGER.severe ("unable to create model");      
         return false;
      }

       // apply axioms from arraylist
       if (!model.applyAxiomsFromArrayList(cc)){
         LOGGER.severe ("unable to apply axioms");      
         return false;
       }
       
       LOGGER.info("got work model from "+ filename);             
       return true;
   }

    //                                                                        source flows                       target flows        instance i.e. target       class
    public Stream<OWLNamedIndividual> findReasonForTarget(List<OWLNamedIndividual> sourceFlows, List<OWLNamedIndividual> targetFlows, OWLNamedIndividual target, OWLClass cls){
       O tmp = getModelByIRI(cls.getIRI());
       MyAxiom ax = tmp.searchForSimpleClassDefinition(cls.getIRI());
       if (ax != null){ // ax.args[0] - property, ax.args[1] - class
          ArrayList<OWLNamedIndividual> lst = new ArrayList();
          // if isSourceOf
          if (ax.args[0].equals(IsSourceOfProperty)) {
             for (Iterator<OWLNamedIndividual> iterator = sourceFlows.stream().iterator(); iterator.hasNext(); ){
                OWLNamedIndividual flow = (OWLNamedIndividual)iterator.next();
                if (model.isReasonerIndividualBelongsToClass(flow.getIRI(),IRI.create(ax.args[1])) ) lst.add (flow);
             }
             return lst.stream();
          }
          
          // if isTargetOf
          if (ax.args[0].equals(IsTargetOfProperty)) {
             for (Iterator<OWLNamedIndividual> iterator = targetFlows.stream().iterator(); iterator.hasNext(); ){
                OWLNamedIndividual flow = (OWLNamedIndividual)iterator.next();
                if (model.isReasonerIndividualBelongsToClass(flow.getIRI(),IRI.create(ax.args[1])) ) lst.add (flow);
             }
             return lst.stream();           
          }
          
          // if isEdgeOf
          // a bit of copy-paste
          if (ax.args[0].equals(IsEdgeOfProperty)) {
             for (Iterator<OWLNamedIndividual> iterator = targetFlows.stream().iterator(); iterator.hasNext(); ){
                OWLNamedIndividual flow = (OWLNamedIndividual)iterator.next();
                if (model.isReasonerIndividualBelongsToClass(flow.getIRI(),IRI.create(ax.args[1])) ) lst.add (flow);
             }
             for (Iterator<OWLNamedIndividual> iterator = sourceFlows.stream().iterator(); iterator.hasNext(); ){
                OWLNamedIndividual flow = (OWLNamedIndividual)iterator.next();
                if (model.isReasonerIndividualBelongsToClass(flow.getIRI(),IRI.create(ax.args[1])) ) lst.add (flow);
             }
             return lst.stream();
                        
          }
          
       }
       return null;
    }
    
    private void says(String str){
       String name = "AIEd";       
       System.out.println(name+": "+str);
    }
    
    public String findAggressors(OWLNamedIndividual target, OWLNamedIndividual threat, List<OWLNamedIndividual> flows){
       //List<OWLNamedIndividual> flows = model.getReasonerObjectPropertyValues(target.getIRI(),IRI.create(IsEdgeOfProperty)).collect(Collectors.toList());
       StringBuffer bf = new StringBuffer();
       for (Iterator<OWLNamedIndividual> iterator = flows.stream().iterator(); iterator.hasNext(); ){
           OWLNamedIndividual  flow = (OWLNamedIndividual)iterator.next();
           
           String prop;
           OWLAxiom ax1 = model.getObjectPropertyAssertionAxiom(IRI.create(HasSourceProperty), flow.getIRI(), target.getIRI());
           if (model.containsAxiom1(ax1)){
              prop = IsAffectedBySourceProperty;
           } else{
              prop = IsAffectedByTargetProperty;
           }
           OWLAxiom ax = model.getObjectPropertyAssertionAxiom(IRI.create(prop), flow.getIRI(), threat.getIRI());
           if (model.containsAxiom1(ax)){           
              bf.append(flow.getIRI().toString());
              bf.append(" ");
           }
       }       
       return bf.toString();
    }

    // old procedure
    public void analyseWithAIEd(){
       // reason the model
       flushModel();
   
       says ("Hello, I love flow based security analysis."); 
       says ("Starting to analize " +model.getIRI() +" ...");
       // get list of flows
       List<OWLNamedIndividual> flows = model.getReasonerInstances(IRI.create(DataFlowClass)).collect(Collectors.toList());
       says("Let me consider flows of this model...");
       says("The model contains "+flows.size()+" data flow(s):");
       // for the flow suggestions
       List<OWLClass> classifiedHasEdge = model.getReasonerSubclasses(IRI.create(ClassifiedHasEdgeClass)).collect(Collectors.toList());
       // get primary type, source & target, also suggestions
       for (Iterator<OWLNamedIndividual> iterator = flows.stream().iterator(); iterator.hasNext(); ){
          // take a flow
          OWLNamedIndividual flow = (OWLNamedIndividual)iterator.next();
          // describe it
          says("The flow " + flow.toString());
          says("... belongs to " + model.classesToString(model.getSearcherTypes(flow)));
          says("... its source " + model.getObjectPropertyValue(flow.getIRI(),IRI.create(HasSourceProperty)));
          says("... its target " + model.getObjectPropertyValue(flow.getIRI(),IRI.create(HasTargetProperty)));
          // take a list of threats
          List<OWLNamedIndividual> threats = model.getReasonerObjectPropertyValues(flow.getIRI(),IRI.create(IsAffectedByProperty)).collect(Collectors.toList());
          for (Iterator<OWLNamedIndividual> iterator5 = threats.stream().iterator(); iterator5.hasNext(); ){
              // take a threat
              OWLNamedIndividual tmp = (OWLNamedIndividual)iterator5.next();
              says("... affected by " + tmp.toString());
          }

          // if some subclass of ClassifiedHasEdge has the suggestsThreat or suggestsThreatCategory properties
          // it is possible to recommend the creation of extra instances of threats
         /* for (Iterator<OWLClass> iterator1 = model.getReasonerTypes(flow).iterator(); iterator1.hasNext(); ){
              OWLClass cls = (OWLClass)iterator1.next();
              if (classifiedHasEdge.contains(cls)){ // check only subclasses of the 'ClassifiedHasEdge' class
                 O tmp = getModelByIRI(cls.getIRI());
                 if (tmp!=null){
                    // a recommendation for threats
                    // !!! takes only one value
                    IRI y = tmp.searchForExpressionValue(tmp.getSearcherSuperClasses(cls.getIRI()),"ObjectSomeValuesFrom",IRI.create(SuggestsThreatProperty));
                    if (y!=null) {
                       String instances = model.instancesToString(model.getReasonerInstances(y)); 
                       says("...I suggest to apply threats of the <"+ y.toString()+ "> class: " +instances);
                    }
                 }
              }
          } */ 
 
       }

       // get list of targets
       List<OWLNamedIndividual> targets = model.getReasonerInstances(IRI.create(TargetClass)).collect(Collectors.toList());
       says("Let me consider targets...");
       says("Given model contains "+targets.size()+" target(s):");
       for (Iterator<OWLNamedIndividual> iterator = targets.stream().iterator(); iterator.hasNext(); ){
          // get a target
          OWLNamedIndividual target = (OWLNamedIndividual)iterator.next();
          says("The " + target.toString()+ " target:");
          // primary types
          says("... belongs to " + model.classesToString(model.getSearcherTypes(target)));
 
          // sourced flows 
          List<OWLNamedIndividual> sourceFlows = model.getReasonerObjectPropertyValues(target.getIRI(),IRI.create(IsSourceOfProperty)).collect(Collectors.toList());
          for (Iterator<OWLNamedIndividual> iterator2 = sourceFlows.stream().iterator(); iterator2.hasNext(); ){
              OWLNamedIndividual tmp = (OWLNamedIndividual)iterator2.next();
              says("... source of " + tmp.toString());
          }
          
          // target flows
          List<OWLNamedIndividual> targetFlows = model.getReasonerObjectPropertyValues(target.getIRI(),IRI.create(IsTargetOfProperty)).collect(Collectors.toList());
          for (Iterator<OWLNamedIndividual> iterator3 = targetFlows.stream().iterator(); iterator3.hasNext(); ){
              OWLNamedIndividual tmp = (OWLNamedIndividual)iterator3.next();
              says("... target of " + tmp.toString());
          }
          
          // all the flows
          List<OWLNamedIndividual> edgeFlows = model.getReasonerObjectPropertyValues(target.getIRI(),IRI.create(IsEdgeOfProperty)).collect(Collectors.toList());
 
          // affected threats
          List<OWLNamedIndividual> threats = model.getReasonerObjectPropertyValues(target.getIRI(),IRI.create(IsAffectedByProperty)).collect(Collectors.toList());
          for (Iterator<OWLNamedIndividual> iterator4 = threats.stream().iterator(); iterator4.hasNext(); ){
              // take a threat
              OWLNamedIndividual threat = (OWLNamedIndividual)iterator4.next();
              says("... affected by " + threat.toString() + " (reasons: "+findAggressors(target,threat,edgeFlows)+")");
          }

          // for suggestions: possible threats & structure
          // list of the 'classified as an edge' classes
         /* List<OWLClass> classifiedIsEdge = model.getReasonerSubclasses(IRI.create(ClassifiedIsEdgeClass)).collect(Collectors.toList());
          for (Iterator<OWLClass> iterator1 = model.getReasonerTypes(target).iterator(); iterator1.hasNext(); ){
              OWLClass cls = (OWLClass)iterator1.next();
              if (classifiedIsEdge.contains(cls)){ // check only subclasses of the 'ClassifiedIsEdge' class
                 O tmp = getModelByIRI(cls.getIRI());
                 if (tmp!=null){
                    String reasons = tmp.instancesToString(findReasonForTarget(sourceFlows,targetFlows,target,cls));
                    // a recommendation for internal structure
                    // !!! takes only one value
                    IRI x = tmp.searchForExpressionValue(tmp.getSearcherSuperClasses(cls.getIRI()),"ObjectSomeValuesFrom",IRI.create(SuggestsProperty));
                    if (x!=null) {
                       String instances = model.instancesToString(model.getReasonerInstances(x));
                       says("...I suggest to apply an internal component of the <"+ x.toString() + "> class (because of "+reasons+"): "+instances);
                    }
                    // a recommendation for threat categories
                    // !!! takes only one value
                    IRI y = tmp.searchForExpressionValue(tmp.getSearcherSuperClasses(cls.getIRI()),"ObjectSomeValuesFrom",IRI.create(SuggestsThreatCategoryProperty));
                    if (y!=null) {
                       String instances = model.classesToString(model.getReasonerDirectSubclasses(y)); 
                       says("...I suggest to apply threats of the <"+ y.toString()+ "> class (because of "+reasons+"): " +instances);
                    }
                    
                    // a recommendation for threats
                    // !!! takes only one value 
                    IRI z = tmp.searchForExpressionValue(tmp.getSearcherSuperClasses(cls.getIRI()),"ObjectSomeValuesFrom",IRI.create(SuggestsThreatProperty));
                    if (z!=null) {
                       says("...I suggest to apply an instance of the <"+ z.toString()+ "> threat class (because of "+reasons+")");
                    }

                 }
              }
          } */
       }
       
       says("Done.");
    }
   

    private void says1(String str){
       //String name = ":";       
       System.out.println(str);
    }
 

    public void analyseWithAIEd1(){
       // reason the model
       flushModel();
   
       says1 ("model: " +model.getIRI());
       // get list of flows
       List<OWLNamedIndividual> flows = model.getReasonerInstances(IRI.create(DataFlowClass)).collect(Collectors.toList());
       says1("total_flows: "+flows.size());
       
       // for the flow suggestions
       List<OWLClass> classifiedHasEdge = model.getReasonerSubclasses(IRI.create(ClassifiedHasEdgeClass)).collect(Collectors.toList());
       // get primary type, source & target, also suggestions
       for (Iterator<OWLNamedIndividual> iterator = flows.stream().iterator(); iterator.hasNext(); ){
          // take a flow
          OWLNamedIndividual flow = (OWLNamedIndividual)iterator.next();
          // describe it
          says1("flow: " + flow.toString());
          says1("  classes: " + model.classesToString1(model.getSearcherTypes(flow)));
          says1("  source: " + model.getObjectPropertyValue(flow.getIRI(),IRI.create(HasSourceProperty)));
          says1("  target: " + model.getObjectPropertyValue(flow.getIRI(),IRI.create(HasTargetProperty)));
          // take a list of threats
          List<OWLNamedIndividual> threats = model.getReasonerObjectPropertyValues(flow.getIRI(),IRI.create(IsAffectedByProperty)).collect(Collectors.toList());
          says1("  threats:");
          
          //todo: implement restrictions
          boolean hasRestrictions = model.isReasonerIndividualBelongsToClass(flow.getIRI(),IRI.create(HasRestrictionsClass));

          for (Iterator<OWLNamedIndividual> iterator5 = threats.stream().iterator(); iterator5.hasNext(); ){
              // take a threat
              OWLNamedIndividual tmp = (OWLNamedIndividual)iterator5.next();
              says1("  - " + tmp.toString());              
          }

          // if some subclass of ClassifiedHasEdge has the suggestsThreat or suggestsThreatCategory properties
          // it is possible to recommend the creation of extra instances of threats
         /* for (Iterator<OWLClass> iterator1 = model.getReasonerTypes(flow).iterator(); iterator1.hasNext(); ){
              OWLClass cls = (OWLClass)iterator1.next();
              if (classifiedHasEdge.contains(cls)){ // check only subclasses of the 'ClassifiedHasEdge' class
                 O tmp = getModelByIRI(cls.getIRI());
                 if (tmp!=null){
                    // a recommendation for threats
                    // !!! takes only one value
                    IRI y = tmp.searchForExpressionValue(tmp.getSearcherSuperClasses(cls.getIRI()),"ObjectSomeValuesFrom",IRI.create(SuggestsThreatProperty));
                    if (y!=null) {
                       String instances = model.instancesToString(model.getReasonerInstances(y)); 
                       says("...I suggest to apply threats of the <"+ y.toString()+ "> class: " +instances);
                    }
                 }
              }
          } */ 
 
       }

       // get list of targets
       List<OWLNamedIndividual> targets = model.getReasonerInstances(IRI.create(TargetClass)).collect(Collectors.toList());
       says1("total_targets: "+targets.size());
       for (Iterator<OWLNamedIndividual> iterator = targets.stream().iterator(); iterator.hasNext(); ){
          // get a target
          OWLNamedIndividual target = (OWLNamedIndividual)iterator.next();
          says1("target: " + target.toString());
          // primary types
          says1("  type: " + model.classesToString(model.getSearcherTypes(target)));
 
          // sourced flows 
          List<OWLNamedIndividual> sourceFlows = model.getReasonerObjectPropertyValues(target.getIRI(),IRI.create(IsSourceOfProperty)).collect(Collectors.toList());
          for (Iterator<OWLNamedIndividual> iterator2 = sourceFlows.stream().iterator(); iterator2.hasNext(); ){
              OWLNamedIndividual tmp = (OWLNamedIndividual)iterator2.next();
              says1("  is_source_of: " + tmp.toString());
          }
          
          // target flows
          List<OWLNamedIndividual> targetFlows = model.getReasonerObjectPropertyValues(target.getIRI(),IRI.create(IsTargetOfProperty)).collect(Collectors.toList());
          for (Iterator<OWLNamedIndividual> iterator3 = targetFlows.stream().iterator(); iterator3.hasNext(); ){
              OWLNamedIndividual tmp = (OWLNamedIndividual)iterator3.next();
              says1("  is_target_of: " + tmp.toString());
          }
          
          // all the flows
          List<OWLNamedIndividual> edgeFlows = model.getReasonerObjectPropertyValues(target.getIRI(),IRI.create(IsEdgeOfProperty)).collect(Collectors.toList());

          boolean hasRestrictions = model.isReasonerIndividualBelongsToClass(target.getIRI(),IRI.create(HasRestrictionsClass));

          // affected threats
          List<OWLNamedIndividual> threats = model.getReasonerObjectPropertyValues(target.getIRI(),IRI.create(IsAffectedByProperty)).collect(Collectors.toList());
          says1("  threats:");

          for (Iterator<OWLNamedIndividual> iterator4 = threats.stream().iterator(); iterator4.hasNext(); ){
              // take a threat
              OWLNamedIndividual threat = (OWLNamedIndividual)iterator4.next();
              
              // check that threat satisfies the target, skip threats from the base model        
              if (hasRestrictions && !isItFromBaseModel(threat.getIRI())){
                  OWLAxiom ax = model.getObjectPropertyAssertionAxiom(IRI.create(SatisfiesProperty),target.getIRI(), threat.getIRI());
                  if (!model.containsAxiom1(ax)) says1("  - " + threat.toString()+ " (not satisfied)");
                  else says1("  - " + threat.toString()+ " (satisfied)");
              } else says1("  - " + threat.toString());
              
              // apply comments and reasons
              O modelOfThreat = getModelByIRI1(threat.getIRI());
              says1("    comment: "+modelOfThreat.getSeacherComment(threat));
              says1("    reasons: "+findAggressors(target,threat,edgeFlows));
          }

       }
       
      // says1("Done.");
    }


    public boolean saveWorkModelToFile(String filename){
       LOGGER.info("trying to save work model as "+ filename);
       return saveToFile(workModel,filename);
    }
   
}
