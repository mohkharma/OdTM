The 'OdTMIntegratedModel.owl' file contains the resulting ontology in the functional
syntax.
- The 'OdTMIntegratedModel.ttl' file (its path is 'applications/generateIM/ttl/') contains the
same data in the RDF format.
- The 'OdTMIntegratedModel_filled.ttl' file (its path is 'applications/generateIM/ttl/')
contains inferred (by automatic reasoning) dataset in RDF.

Both the root concept 'Threat' and the 'ATTCKTechnique' concept represent the ATT&CK
techniques. We follow an approach of the ATT&CK enumeration (Enterprise Matrix,
https://github.com/mitre-attack/attack-stix-data) that is built with the STIX format and saved as a
JSON file, in which the techniques are named as 'attack-pattern' items with own machine-readable
IDs and references to the ATT&CK techniques (the 'external_references' items, the 'source_name'
field with the 'mitre-attack' value). So, the threat instances follow the technique instances by the
'refToATTCK' property. The ATT&CK STIX representation also has the tactic entities that are
mapped with the attack patterns by the 'refToTactic' property in the ontology.
The 'CAPEC' concept represents another kind of attack patterns, taken from an XML file
(https://capec.mitre.org). The ATT&CK techniques have external references to the CAPEC entities
(the ATT&CK enumeration) that are placed in the ontology by the 'refToCAPEC' property. The
CAPEC entities also have backward references to the techniques (the 'Taxonomy_Mapping' tag and
the 'ATTACK' attribute in the CAPEC enumeration) and reflected by the 'isRefToATTCK' property
in the ontology.

The 'CWE' concept indicates entities of the weakness enumeration, which are provided by
an XML file (https://cwe.mitre.org). The CAPEC items have references to CWE (the
'Related_Weakness' tag and the 'CWE_ID' attribute in the CAPEC enumeration), that is shown by
the 'refToCWE' property in the ontology. And the CWE enumeration has links to CAPECs (the
'Related_Attack_Pattern' and the 'CAPEC_ID' attribute), depicted by the 'isRefToCAPEC'
properties of the ontology.
Also, CWEs refer to CVEs (the 'Observed_Example' tag), that is represented by the
'refToCVE' property in the ontology. So, the knowledge base has only CVEs mentioned in the CWE
enumeration.