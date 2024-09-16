#purpose of this script is to:
#1. Connect VCDB to VERIS-ATT&CK Mappings
#2. Connect ATT&CK-D3FEND mappings to VERIS-ATT&CK Mappings
#3. Classify D3FEND countermeasures based on Zero Trust principles
#4. Build a dataset that maps Zero Trust to VCDB incidents

#RESOURCES:
#VCDB - https://github.com/vz-risk/VCDB/tree/master OR https://verisframework.org/vcdb.html
#VERIS-ATT&CK mappings - https://github.com/center-for-threat-informed-defense/attack_to_veris/tree/main/mappings/veris-1.3.7/input/enterprise
# OR https://center-for-threat-informed-defense.github.io/mappings-explorer/external/veris/attack-12.1/domain-mobile/veris-1.3.7/
#MITRE D3FEND to Zero Trust mappings - https://www.f5.com/pdf/report/office-of-the-cto-zero-trust-and-the-mitre-framework.pdf
#MITRE D3FEND (for ATT&CK mapping lookup) - https://d3fend.mitre.org/api/offensive-technique/attack/

library(dplyr)
library(jsonlite)
vcdb_dbir <- read.csv("vcdb_dbir.csv", header=TRUE, sep=",")
MITRE_defend_json_urls <- read.csv("MITRE_defend_json_urls.csv", header=TRUE, sep=",")
#As of April 2024, MITRE D3FEND only has mappings for Enterprise ATT&CK entries
MITRE_defend_json_urls <- MITRE_defend_json_urls[ which(MITRE_defend_json_urls$X == "Enterprise"), ]

#MITRE D3FEND json incorrectly associates MITRE ATT&CK techniques with more tactics than intended
#so scraping the MITRE ATT&CK web page will accurately grab the tactics and related techniques
library(rvest)
library(purrr)
library(httr)
mitreAttackHtml <- read_html("MITREATTACK.html")

#code for listing all unique classes of all nodes in a set of html
mitreAttackHtml %>% 
    html_nodes("*") %>% 
    html_attr("class") %>% 
    unique()

#the following code crawls through HTML structure to get to
#the HTML table that contains tactics and techniques
#then extract the data from the HTML
TechniqueTableRows <- 
    mitreAttackHtml %>% 
    html_nodes('.matrix.side')

techniqueHeaderNames <- 
    TechniqueTableRows %>% 
    html_nodes('thead') %>% 
    html_nodes('tr') %>%
    html_nodes('.tactic.name') %>% 
    html_text()

techniques <- 
    TechniqueTableRows %>% 
    html_nodes('tbody') %>% 
    html_nodes('tr') %>%
    html_nodes('.tactic')

#create empty data frame that will hold technique name and its tactic name
attackColumnNames <- c("off_tech_id","off_tech_label","off_tactic_label")
attacksWithTactics <- data.frame(matrix(nrow=0, ncol=length(attackColumnNames)))
colnames(attacksWithTactics) <- attackColumnNames
nrow(attacksWithTactics)

for(i in 1:length(techniques)){
    currentTactic <- techniques[i]
    
    #get row that contains supertechnique and possible subtechniques
    superTechniqueRows <-
        currentTactic %>%
        html_nodes('.techniques-table') %>%
        html_nodes('tbody') %>%
        html_nodes('.technique-row')
    
    currentTacticTechniques <- 
        superTechniqueRows %>%
        html_nodes('.technique-cell') %>%
        html_nodes('a') %>% html_text()
    
    currentTacticTechniquesIds <- 
        superTechniqueRows %>%
        html_nodes('.technique-cell') %>%
        html_nodes('a') %>% html_attr('data-original-title')
    
    for (j in 1:length(currentTacticTechniques)){
        currentDfLength <- nrow(attacksWithTactics)
        
        #if a supertechnique, remove the trailing parentheses from the technique label
        if(nchar(currentTacticTechniquesIds[j]) == 5){
            subTechniqueCounter <- 0
            for (k in 1:length(currentTacticTechniquesIds)){
                idToCheck <- currentTacticTechniquesIds[k]
                if(substr(idToCheck,1,5) == currentTacticTechniquesIds[j]){
                    subTechniqueCounter <- subTechniqueCounter+1
                }
            }
            
            if(subTechniqueCounter > 1){
                currentTacticTechniques[j] <- substr(currentTacticTechniques[j],1,nchar(currentTacticTechniques[j])-nchar(paste(" (",subTechniqueCounter-1,")",sep = "")))
            }
        }
        
        attacksWithTactics[currentDfLength+1,"off_tech_id"] <- currentTacticTechniquesIds[j]
        attacksWithTactics[currentDfLength+1,"off_tech_label"] <- currentTacticTechniques[j]
        attacksWithTactics[currentDfLength+1,"off_tactic_label"] <- techniqueHeaderNames[i]
    }
}


#loop to download json files from MITRE D3FEND
for (i in 1:nrow(MITRE_defend_json_urls)){
    currentUrl <- MITRE_defend_json_urls[i,]$jsonURL
    download.file(url = currentUrl, destfile = substr(currentUrl,nchar(currentUrl)-9,nchar(currentUrl)))
}

#loop to load MITRE D3FEND/ATT&CK mappings into one big data frame
#first loop creates individual csv files based on individual json files for ATT&CK types
for (i in 1:nrow(MITRE_defend_json_urls)){
    currentUrl <- MITRE_defend_json_urls[i,]$jsonURL
    currentFilename <- substr(currentUrl,nchar(currentUrl)-9,nchar(currentUrl))
    jsonData <- fromJSON(currentFilename)
    resultsBindings <- jsonData$off_to_def$results$bindings
    write.csv(resultsBindings, paste(currentFilename,".csv",sep=""))
}

#loop through the individual csv files to combine major D3FEND categories
#into a single data frame
for (i in 1:nrow(MITRE_defend_json_urls)){
    currentUrl <- MITRE_defend_json_urls[i,]$jsonURL
    currentFilename <- substr(currentUrl,nchar(currentUrl)-9,nchar(currentUrl))
    try({
        currentDfSub <- read.csv(currentFilename, header=TRUE, sep=",")
        if(i==1){
            fullDfSub <- currentDfSub
        }
        else{
            if(nrow(currentDfSub) > 0){
                fullDfSub <- bind_rows(fullDfSub, currentDfSub)
            }
        }
    })
}

#output the data frame into a csv containing all ATT&CK/D3FEND relationships
#for major ATT&CK categories
write.csv(fullDf, "MITRE_DefendAttack_relationships.csv")

#get ATT&CK subtechniques
for (i in 1:nrow(MITRE_defend_json_urls)){
    currentUrl <- MITRE_defend_json_urls[i,]$jsonURL
    currentFilename <- substr(currentUrl,nchar(currentUrl)-9,nchar(currentUrl))
    jsonData <- fromJSON(currentFilename)
    currentSubTechniques <- jsonData$subtechniques$`@graph`
    if(i==1){ #if first entry, create the df
        subTechniques <- currentSubTechniques
    }
    else{ #if after the first entry, add to the df
        if (length(currentSubTechniques) > 1){
            subTechniques <- bind_rows(subTechniques, currentSubTechniques)
        }
    }
}

#grab just the subTechnique IDs and write to a csv
subSelect <- subTechniques %>% select(`@id`)
write.csv(subSelect, "MITRESubTechniques.csv")

#at this point, I used excel to eliminate major ATT&CK category entries,
#leaving just the subtechniques in the csv file

mitreSubTechniques <- read.csv("MITRESubTechniques.csv", header=TRUE, sep=",")
rootUrl <- "https://d3fend.mitre.org/api/offensive-technique/attack/"

#download the json files for the ATT&CK subtechniques
for (i in 1:nrow(mitreSubTechniques)){
    currentUrl <- paste(rootUrl,mitreSubTechniques[i,1],".json", sep = "")
    download.file(url = currentUrl, destfile = substr(currentUrl,nchar(currentUrl)-13,nchar(currentUrl)))
}

#loop to load MITRE D3FEND/ATT&CK mappings (subtechniques) into one big data frame
#first loop creates individual csv's from the json files
for (i in 1:nrow(mitreSubTechniques)){
    currentFilename <- paste(mitreSubTechniques[i,1],".json", sep = "")
    jsonData <- fromJSON(currentFilename)
    #instead of combining into a dataframe, created separate csv files
    resultsBindings <- jsonData$off_to_def$results$bindings
    write.csv(resultsBindings, paste(currentFilename,".csv",sep=""))
}

#second loop combines the individual csv's into one big data frame
for (i in 1:nrow(mitreSubTechniques)){
    currentFilename <- paste(mitreSubTechniques[i,1],".json.csv", sep = "")
    try({
        currentDfSub <- read.csv(currentFilename, header=TRUE, sep=",")
        if(i==1){
            fullDfSub <- currentDfSub
        }
        else{
            if(nrow(currentDfSub) > 0){
                fullDfSub <- bind_rows(fullDfSub, currentDfSub)
            }
        }
    })
}

fullDf <- bind_rows(fullDf, fullDfSub)
write.csv(fullDf, "MITRE_DefendAttack_relationships.csv")

#filter out the rows that only have offensive but not defensive tactics
mitreAttackToDefend <- read.csv("MITRE_DefendAttack_relationships.csv", header=TRUE, sep=",")
mitreAttackToDefend <- mitreAttackToDefend[ which(!is.na(mitreAttackToDefend$def_tactic_label.type)), ]
mitreAttackToDefend <- fullDf[ which(!is.na(fullDf$def_tactic_label.type)), ]

#load data frames from mapping files
verisCapabilities <- read.csv("Data/VERIS_category_ids_mapped_to_MITRE.csv", header=TRUE, sep=",")
verisToMitreAttack <- read.csv("Data/veris-1.3.7_attack-12.1-enterprise.csv", header=TRUE, sep=",")
verisToMitreAttack$capability_id <- gsub(" ",".",verisToMitreAttack$capability_id)
verisToMitreAttack$capability_id <- gsub("-",".",verisToMitreAttack$capability_id)
verisToMitreAttack$capability_id <- gsub("/",".",verisToMitreAttack$capability_id)

verisToMitreAttackMappable <- verisToMitreAttack[which(verisToMitreAttack$mapping_type!="non_mappable"),]
uniqueMitreAttacks <- data.frame(unique(verisToMitreAttackMappable$attack_object_id))
colnames(uniqueMitreAttacks) <- c("attack_object_id")

#clean the mitreAttackToDefend data frame so that it only contains rows where the offensive technique matches its actual tactic label
mitreAttackToDefendCleaned <- data.frame(matrix(nrow=0, ncol=length(colnames(mitreAttackToDefend))))
colnames(mitreAttackToDefendCleaned) <- colnames(mitreAttackToDefend)

for(i in 1:nrow(attacksWithTactics)){
    currentAttackId <- attacksWithTactics[i, "off_tech_id"]
    currentAttackLabel <- attacksWithTactics[i, "off_tech_label"]
    currentAttackTactic <- attacksWithTactics[i, "off_tactic_label"]
    
    currentAttackDefendSubset <- mitreAttackToDefend[which(mitreAttackToDefend$off_tech_id.value == currentAttackId & tolower(mitreAttackToDefend$off_tactic_label.value) == tolower(currentAttackTactic)),]
    if(i < 2){
        mitreAttackToDefendCleaned <- currentAttackDefendSubset
    }
    else{
        mitreAttackToDefendCleaned <- bind_rows(mitreAttackToDefendCleaned, currentAttackDefendSubset)
    }
    
}

#eliminate duplicate entries
mitreAttackToDefendCleaned <- 
    mitreAttackToDefendCleaned[,3:ncol(mitreAttackToDefendCleaned)] %>% 
    dplyr::select(off_tech_id.value,off_tech_label.value, def_tactic_label.value, def_tech_parent_label.value, def_tech_label.value) %>%
    distinct()

write.csv(mitreAttackToDefendCleaned,"MITREAttackToDefendRelationships_cleaned.csv")


#create dataset of unique MITRE D3FEND techniques
uniqueDefendTechniques_all <- unique(mitreAttackToDefend$def_tech_label.value)

for(i in 1:length(uniqueDefendTechniques_all)){
    #get info on technique
    currentTechnique <- mitreAttackToDefend[which(mitreAttackToDefend$def_tech_label.value==uniqueDefendTechniques_all[i]),]
    currentTechniqueRecord <- currentTechnique[1,27:ncol(currentTechnique)]
    if(i==1){
        uniqueDefendTechniquesDf <- currentTechniqueRecord
    }
    else{
        uniqueDefendTechniquesDf <- bind_rows(uniqueDefendTechniquesDf, currentTechniqueRecord)
    }
}

mitreDefendModel <- uniqueDefendTechniquesDf[which(uniqueDefendTechniquesDf$def_tactic_label.value=="Model"),]
mitreDefendHarden <- uniqueDefendTechniquesDf[which(uniqueDefendTechniquesDf$def_tactic_label.value=="Harden"),]
mitreDefendDetect <- uniqueDefendTechniquesDf[which(uniqueDefendTechniquesDf$def_tactic_label.value=="Detect"),]
mitreDefendIsolate <- uniqueDefendTechniquesDf[which(uniqueDefendTechniquesDf$def_tactic_label.value=="Isolate"),]
mitreDefendDeceive <- uniqueDefendTechniquesDf[which(uniqueDefendTechniquesDf$def_tactic_label.value=="Deceive"),]
mitreDefendEvict <- uniqueDefendTechniquesDf[which(uniqueDefendTechniquesDf$def_tactic_label.value=="Evict"),]
mitreDefendRestore <- uniqueDefendTechniquesDf[which(uniqueDefendTechniquesDf$def_tactic_label.value=="Restore"),]


###########BIG LOOP TO ADD MITRE DATA TO VCDB -- TAKES ~20 MINUTES TO RUN#############
for(i in 1:nrow(vcdb_dbir)){
    isEnterprise <- FALSE
    #loop through each of the capability_id values that are mapped to MITRE ATT&CK
    for(j in 1:nrow(verisCapabilities)){
        currentCapabilityId <- verisCapabilities[j,1]
        #check current incident from VCDB to see if it's classified with the capability
        incidentIncludesCapability <- vcdb_dbir[i, currentCapabilityId]
        if(incidentIncludesCapability){
            #at least one capability is "enterprise" so set isEnterprise equal to true
            isEnterprise <- TRUE
            #set up lists to hold MITRE D3FEND labels
            modelList <- list()
            hardenList <- list()
            detectList <- list()
            isolateList <- list()
            deceiveList <- list()
            evictList <- list()
            restoreList <- list()
            modelListCounter <- 0
            hardenListCounter <- 0
            detectListCounter <- 0
            isolateListCounter <- 0
            deceiveListCounter <- 0
            evictListCounter <- 0
            restoreListCounter <- 0
            #look up the associated MITRE ATT&CK entries for that capability
            #idSubstring <- substr(currentCapabilityId,nchar(currentCapabilityId)-4,nchar(currentCapabilityId))
            if (substr(currentCapabilityId,nchar(currentCapabilityId)-3,nchar(currentCapabilityId))==".Yes"){
                currentCapabilityId <- substr(currentCapabilityId,1,nchar(currentCapabilityId)-4)
            }
            currentMitreAttacks <- verisToMitreAttack[ which(verisToMitreAttack$capability_id == currentCapabilityId), ]
            currentMitreAttacks <- data.frame(unique(currentMitreAttacks$attack_object_id))
            colnames(currentMitreAttacks) <- c("attack_object_id")

            for(k in 1:nrow(currentMitreAttacks)){
                #add a column for the current MITRE ATT&CK id to the VCDB and set it to TRUE
                currentMitreAttackId <- currentMitreAttacks[k,"attack_object_id"]
                vcdb_dbir[i, paste("off_tech_id_", currentMitreAttackId,sep = "")] <- TRUE
                #look up associated MITRE D3FEND countermeasures for current ATT&CK id
                currentCountermeasures <- mitreAttackToDefendCleaned[which(mitreAttackToDefendCleaned$off_tech_id.value==currentMitreAttackId), ]
                if (nrow(currentCountermeasures) > 0){
                    for(l in 1:nrow(currentCountermeasures)){
                        currentDefendCategory <- currentCountermeasures[l,"def_tactic_label.value"]
                        currentDefendLabel <- currentCountermeasures[l,"def_tech_label.value"]
                        #check if the defend category matches one of the ZT metrics
                        #if so, set up new columns and set them to TRUE
                        if (currentDefendCategory == "Model" && !is.na(currentDefendCategory)){
                            if(length(modelList) == 0){
                                modelListCounter <- modelListCounter + 1
                                modelList[modelListCounter] <- currentDefendLabel
                            }
                            else{
                                if(currentDefendLabel %in% modelList  == FALSE){
                                    modelListCounter <- modelListCounter + 1
                                    modelList[modelListCounter] <- currentDefendLabel
                                }
                            }
                        }
                        if (currentDefendCategory == "Harden" && !is.na(currentDefendCategory)){
                            vcdb_dbir[i, "zt_method_authentication"] <- TRUE
                            vcdb_dbir[i, "zt_method_accesscontrol"] <- TRUE
                            vcdb_dbir[i, "zt_principle_leastprivilege"] <- TRUE
                            vcdb_dbir[i, "zt_principle_explicitlyverify"] <- TRUE
                            #print(paste("Harden Count: ", length(hardenList),sep = ""))
                            if(length(hardenList) == 0){
                                hardenListCounter <- hardenListCounter + 1
                                hardenList[hardenListCounter] <- currentDefendLabel
                            }
                            else{
                                if(currentDefendLabel %in% hardenList  == FALSE){
                                    hardenListCounter <- hardenListCounter + 1
                                    hardenList[hardenListCounter] <- currentDefendLabel
                                }
                            }
                        }
                        if (currentDefendCategory == "Detect" && !is.na(currentDefendCategory)){
                            vcdb_dbir[i, "zt_method_visibility"] <- TRUE
                            vcdb_dbir[i, "zt_method_contextualanalysis"] <- TRUE
                            vcdb_dbir[i, "zt_principle_assessreassess"] <- TRUE
                            #print(paste("Detect Count: ", length(detectList),sep = ""))
                            if(length(detectList) == 0){
                                detectListCounter <- detectListCounter + 1
                                detectList[detectListCounter] <- currentDefendLabel
                            }
                            else{
                                if(currentDefendLabel %in% detectList  == FALSE){
                                    detectListCounter <- detectListCounter + 1
                                    detectList[detectListCounter] <- currentDefendLabel
                                }
                            }
                        }
                        
                        if ((currentDefendCategory == "Isolate" | currentDefendCategory == "Deceive" | currentDefendCategory == "Evict") && !is.na(currentDefendCategory)){
                            vcdb_dbir[i, "zt_method_remediation"] <- TRUE
                            vcdb_dbir[i, "zt_principle_assumebreaches"] <- TRUE
                            #print(paste("Isolate Count: ", length(hardenList),sep = ""))
                            #print(paste("Deceive Count: ", length(hardenList),sep = ""))
                            #print(paste("Evict Count: ", length(hardenList),sep = ""))
                            
                            #isolateDeceiveEvictTotal <- isolateDeceiveEvictTotal+1
                            if (currentDefendCategory == "Isolate"){
                                if(length(isolateList) == 0){
                                    isolateListCounter <- isolateListCounter + 1
                                    isolateList[isolateListCounter] <- currentDefendLabel
                                }
                                else{
                                    if(currentDefendLabel %in% isolateList  == FALSE){
                                        isolateListCounter <- isolateListCounter + 1
                                        isolateList[isolateListCounter] <- currentDefendLabel
                                    }
                                }
                            }
                            if (currentDefendCategory == "Deceive"){
                                if(length(deceiveList) == 0){
                                    deceiveListCounter <- deceiveListCounter + 1
                                    deceiveList[deceiveListCounter] <- currentDefendLabel
                                }
                                else{
                                    if(currentDefendLabel %in% deceiveList  == FALSE){
                                        deceiveListCounter <- deceiveListCounter + 1
                                        deceiveList[deceiveListCounter] <- currentDefendLabel
                                    }
                                }
                            }
                            if (currentDefendCategory == "Evict"){
                                if(length(evictList) == 0){
                                    evictListCounter <- evictListCounter + 1
                                    evictList[evictListCounter] <- currentDefendLabel
                                }
                                else{
                                    if(currentDefendLabel %in% evictList  == FALSE){
                                        evictListCounter <- evictListCounter + 1
                                        evictList[evictListCounter] <- currentDefendLabel
                                    }
                                }
                            }
                        }
                        if (currentDefendCategory == "Restore" && !is.na(currentDefendCategory)){
                            if(length(restoreList) == 0){
                                restoreListCounter <- restoreListCounter + 1
                                restoreList[restoreListCounter] <- currentDefendLabel
                            }
                            else{
                                if(currentDefendLabel %in% restoreList  == FALSE){
                                    restoreListCounter <- restoreListCounter + 1
                                    restoreList[restoreListCounter] <- currentDefendLabel
                                }
                            }
                        }
                    }
                }
            }
            
            if(length(modelList) != 0){
                #vcdb_dbir[i, "zt_harden_list"] <- list()
                #vcdb_dbir[i, "zt_harden_list"] <- as.list(hardenList)
                vcdb_dbir[i, "zt_model_count"] <- length(modelList)
            }
            else{
                vcdb_dbir[i, "zt_model_count"] <- 0
            }
            if(length(hardenList) != 0){
                #vcdb_dbir[i, "zt_harden_list"] <- list()
                #vcdb_dbir[i, "zt_harden_list"] <- as.list(hardenList)
                vcdb_dbir[i, "zt_harden_count"] <- length(hardenList)
            }
            else{
                vcdb_dbir[i, "zt_harden_count"] <- 0
            }
            
            if(length(detectList) != 0){
                #vcdb_dbir[i, "zt_detect_list"] <- list()
                #vcdb_dbir[i, "zt_detect_list"] <- as.list(detectList)
                vcdb_dbir[i, "zt_detect_count"] <- length(detectList)
            }
            else{
                vcdb_dbir[i, "zt_detect_count"] <- 0
            }
            
            if(length(isolateList) != 0){
                #vcdb_dbir[i, "zt_isolate_list"] <- list()
                #vcdb_dbir[i, "zt_isolate_list"] <- as.list(isolateList)
                vcdb_dbir[i, "zt_isolate_count"] <- length(isolateList)
            }
            else{
                vcdb_dbir[i, "zt_isolate_count"] <- 0
            }
            
            if(length(deceiveList) != 0){
                #vcdb_dbir[i, "zt_deceive_list"] <- list()
                #vcdb_dbir[i, "zt_deceive_list"] <- as.list(deceiveList)
                vcdb_dbir[i, "zt_deceive_count"] <- length(deceiveList)
            }
            else{
                vcdb_dbir[i, "zt_deceive_count"] <- 0
            }
            
            if(length(evictList) != 0){
                #vcdb_dbir[i, "zt_evict_list"] <- list()
                #vcdb_dbir[i, "zt_evict_list"] <- as.list(evictList)
                vcdb_dbir[i, "zt_evict_count"] <- length(evictList)
            }
            else{
                vcdb_dbir[i, "zt_evict_count"] <- 0
            }
            if(length(restoreList) != 0){
                #vcdb_dbir[i, "zt_harden_list"] <- list()
                #vcdb_dbir[i, "zt_harden_list"] <- as.list(hardenList)
                vcdb_dbir[i, "zt_restore_count"] <- length(restoreList)
            }
            else{
                vcdb_dbir[i, "zt_model_count"] <- 0
            }
            
            vcdb_dbir[i, "zt_isolate_deceive_evict_total"] <- vcdb_dbir[i, "zt_isolate_count"] + vcdb_dbir[i, "zt_deceive_count"] + vcdb_dbir[i, "zt_evict_count"]
        }
    }
    vcdb_dbir[i, "is_enterprise"] <- isEnterprise
    #print out the vcdb iterator and the timestamp to monitor progress
    print(paste(i,Sys.time(),sep = " "))
}

#filter out incidents that are not 'enterprise'
vcdb_dbir_enterprise <- vcdb_dbir[which(vcdb_dbir$is_enterprise==TRUE),]
write.csv(vcdb_dbir, "vcdb_dbir_enterprise.csv")



#LOOP TO CREATE ATTACK COUNT DATASET (one MITRE attack id per row)
vcdb_mitre_attack_counts <- data.frame()

for(i in 1:nrow(uniqueMitreAttacks)){
    currentAttackId <- uniqueMitreAttacks[i, "attack_object_id"]
    columnName <- paste("off_tech_id_", currentAttackId,sep = "")
    
    #get technique label and tactic label
    fullAttackInfo <- attacksWithTactics[which(attacksWithTactics$off_tech_id==currentAttackId),]
    
    #add attack info to the dataframe
    vcdb_mitre_attack_counts[i,"off_tech_id"] <- currentAttackId
    vcdb_mitre_attack_counts[i,"off_tech_label"] <- fullAttackInfo[1,"off_tech_label"]
    
    uniqueTacticLabels <- unique(fullAttackInfo$off_tactic_label)
    for(tactic in 1:length(uniqueTacticLabels)){
        currentTacticLabel <- uniqueTacticLabels[tactic]
        tacticColumnName <- paste("off_tactic_label_",currentTacticLabel,sep = "")
        vcdb_mitre_attack_counts[i,tacticColumnName] <- TRUE
    }
    
    #check if columnName exists in data frame
    if(columnName %in% colnames(vcdb_dbir_enterprise))
    {
        currentAttackCountDf <- vcdb_dbir_enterprise %>% count(across(columnName))
        currentAttackCount <- currentAttackCountDf[which(currentAttackCountDf[,columnName]==TRUE),"n"]
        currentAttackPct <- currentAttackCount / nrow(vcdb_dbir_enterprise)
        vcdb_mitre_attack_counts[i,"totalCount"] <- currentAttackCount
        vcdb_mitre_attack_counts[i,"totalPct"] <- currentAttackPct
        
        #loop to get counts and frequencies by year
        for (j in 2015:2024){
            currentYear <- as.character(j)
            
            # get subset of vcdb data for current year in loop
            vcdb_by_year <- vcdb_dbir_enterprise[which(vcdb_dbir_enterprise$plus.dbir_year==currentYear),]

            vcdb_by_year_by_attack <- vcdb_by_year[which(vcdb_by_year[,columnName]==TRUE),]
            vcdb_mitre_attack_counts[i,paste("X",currentYear,"Count",sep = "")] <- nrow(vcdb_by_year_by_attack)
            vcdb_mitre_attack_counts[i,paste("X",currentYear,"Pct",sep = "")] <- nrow(vcdb_by_year_by_attack) / nrow(vcdb_by_year)

        }
    }
    
    print(paste(i,Sys.time(),sep = " "))
    
}

#dummy code the attack tactic type
vcdb_mitre_attack_counts$off_tactic_label_Collection <- ifelse(is.na(vcdb_mitre_attack_counts$off_tactic_label_Collection),0,1)
vcdb_mitre_attack_counts$`off_tactic_label_Command and Control` <- ifelse(is.na(vcdb_mitre_attack_counts$`off_tactic_label_Command and Control`),0,1)
vcdb_mitre_attack_counts$`off_tactic_label_Credential Access` <- ifelse(is.na(vcdb_mitre_attack_counts$`off_tactic_label_Credential Access`),0,1)
vcdb_mitre_attack_counts$`off_tactic_label_Defense Evasion` <- ifelse(is.na(vcdb_mitre_attack_counts$`off_tactic_label_Defense Evasion`),0,1)
vcdb_mitre_attack_counts$off_tactic_label_Discovery <- ifelse(is.na(vcdb_mitre_attack_counts$off_tactic_label_Discovery),0,1)
vcdb_mitre_attack_counts$off_tactic_label_Execution <- ifelse(is.na(vcdb_mitre_attack_counts$off_tactic_label_Execution),0,1)
vcdb_mitre_attack_counts$off_tactic_label_Exfiltration <- ifelse(is.na(vcdb_mitre_attack_counts$off_tactic_label_Exfiltration),0,1)
vcdb_mitre_attack_counts$off_tactic_label_Impact <- ifelse(is.na(vcdb_mitre_attack_counts$off_tactic_label_Impact),0,1)
vcdb_mitre_attack_counts$`off_tactic_label_Initial Access` <- ifelse(is.na(vcdb_mitre_attack_counts$`off_tactic_label_Initial Access`),0,1)
vcdb_mitre_attack_counts$`off_tactic_label_Lateral Movement` <- ifelse(is.na(vcdb_mitre_attack_counts$`off_tactic_label_Lateral Movement`),0,1)
vcdb_mitre_attack_counts$off_tactic_label_Persistence <- ifelse(is.na(vcdb_mitre_attack_counts$off_tactic_label_Persistence),0,1)
vcdb_mitre_attack_counts$`off_tactic_label_Privilege Escalation` <- ifelse(is.na(vcdb_mitre_attack_counts$`off_tactic_label_Privilege Escalation`),0,1)
vcdb_mitre_attack_counts$off_tactic_label_Reconnaissance <- ifelse(is.na(vcdb_mitre_attack_counts$off_tactic_label_Reconnaissance),0,1)
vcdb_mitre_attack_counts$`off_tactic_label_Resource Development` <- ifelse(is.na(vcdb_mitre_attack_counts$`off_tactic_label_Resource Development`),0,1)


# get defend type counts for each attack
for(i in 1:nrow(vcdb_mitre_attack_counts)){
    #set initial defend counts to 0
    modelCount <- 0
    hardenCount <- 0
    detectCount <- 0
    isolateCount <- 0
    deceiveCount <- 0
    evictCount <- 0
    restoreCount <- 0
    #get the current attack's MITRE id
    currentAttackId <- vcdb_mitre_attack_counts[i,1]
    #currentAttackId <- substr(currentAttackId,nchar(leadText)+1,nchar(currentAttackId))
    #look up the attack category for the current attack
    
    #look up the unique defend techniques for the current attack
    mitreDefendByAttack <- mitreAttackToDefendCleaned[which(mitreAttackToDefendCleaned$off_tech_id.value==currentAttackId),]
    uniqueDefendTechniques <- unique(mitreDefendByAttack$def_tech_label.value)
    if(length(uniqueDefendTechniques) > 0){
        for(j in 1:length(uniqueDefendTechniques)){
            currentMitreDefendTechnique <- mitreDefendByAttack[which(mitreDefendByAttack$def_tech_label.value==uniqueDefendTechniques[j]),]
            if(currentMitreDefendTechnique[1,"def_tactic_label.value"]=="Model"){
                modelCount <- modelCount + 1
            }
            if(currentMitreDefendTechnique[1,"def_tactic_label.value"]=="Harden"){
                hardenCount <- hardenCount + 1
            }
            if(currentMitreDefendTechnique[1,"def_tactic_label.value"]=="Detect"){
                detectCount <- detectCount + 1
            }
            if(currentMitreDefendTechnique[1,"def_tactic_label.value"]=="Isolate"){
                isolateCount <- isolateCount + 1
            }
            if(currentMitreDefendTechnique[1,"def_tactic_label.value"]=="Deceive"){
                deceiveCount <- deceiveCount + 1
            }
            if(currentMitreDefendTechnique[1,"def_tactic_label.value"]=="Evict"){
                evictCount <- evictCount + 1
            }
            if(currentMitreDefendTechnique[1,"def_tactic_label.value"]=="Restore"){
                restoreCount <- restoreCount + 1
            }
        }
    }
    
    vcdb_mitre_attack_counts[i,"ModelCount"] <- modelCount
    vcdb_mitre_attack_counts[i,"ModelPct"] <- modelCount / nrow(mitreDefendModel)
    vcdb_mitre_attack_counts[i,"HardenCount"] <- hardenCount
    vcdb_mitre_attack_counts[i,"HardenPct"] <- hardenCount / nrow(mitreDefendHarden)
    vcdb_mitre_attack_counts[i,"DetectCount"] <- detectCount
    vcdb_mitre_attack_counts[i,"DetectPct"] <- detectCount / nrow(mitreDefendDetect)
    vcdb_mitre_attack_counts[i,"IsolateCount"] <- isolateCount
    vcdb_mitre_attack_counts[i,"IsolatePct"] <- isolateCount / nrow(mitreDefendIsolate)
    vcdb_mitre_attack_counts[i,"DeceiveCount"] <- deceiveCount
    vcdb_mitre_attack_counts[i,"DeceivePct"] <- deceiveCount / nrow(mitreDefendDeceive)
    vcdb_mitre_attack_counts[i,"EvictCount"] <- evictCount
    vcdb_mitre_attack_counts[i,"EvictPct"] <- evictCount / nrow(mitreDefendEvict)
    vcdb_mitre_attack_counts[i,"RestoreCount"] <- restoreCount
    vcdb_mitre_attack_counts[i,"RestorePct"] <- restoreCount / nrow(mitreDefendRestore)
    vcdb_mitre_attack_counts[i,"IsolateDeceiveEvictCount"] <- isolateCount + deceiveCount + evictCount
    vcdb_mitre_attack_counts[i,"IsolateDeceiveEvictPct"] <- (isolateCount + deceiveCount + evictCount) / (nrow(mitreDefendIsolate) + nrow(mitreDefendDeceive) + nrow(mitreDefendEvict))
    
    #look up attack occurrences for current mitre attack type
    #currentAttackId <- "T1001"
    attackLookupCol <- paste("off_tech_id_",currentAttackId,sep="")
    if(attackLookupCol %in% colnames(vcdb_dbir_enterprise))
    {
        mitreAttackOccurrences <- vcdb_dbir_enterprise[which(vcdb_dbir_enterprise[,attackLookupCol]==TRUE),]
        #get industry sector counts for the attack type
        attackIndustryCounts <- count(mitreAttackOccurrences, victim.industry.name)
        
        for(j in 1:nrow(attackIndustryCounts)){
            vcdb_mitre_attack_counts[i, paste("industry.",attackIndustryCounts[j,"victim.industry.name"],sep="")] <- attackIndustryCounts[j,"n"]
        }
    }
}

#dummy code the MITRE D3FEND tactic types
vcdb_mitre_attack_counts$def_tactic_model <- ifelse(vcdb_mitre_attack_counts$ModelCount > 0, 1, 0)
vcdb_mitre_attack_counts$def_tactic_harden <- ifelse(vcdb_mitre_attack_counts$HardenCount > 0, 1, 0)
vcdb_mitre_attack_counts$def_tactic_detect <- ifelse(vcdb_mitre_attack_counts$DetectCount > 0, 1, 0)
vcdb_mitre_attack_counts$def_tactic_isolate <- ifelse(vcdb_mitre_attack_counts$IsolateCount > 0, 1, 0)
vcdb_mitre_attack_counts$def_tactic_deceive <- ifelse(vcdb_mitre_attack_counts$DeceiveCount > 0, 1, 0)
vcdb_mitre_attack_counts$def_tactic_evict <- ifelse(vcdb_mitre_attack_counts$EvictCount > 0, 1, 0)
vcdb_mitre_attack_counts$def_tactic_restore <- ifelse(vcdb_mitre_attack_counts$RestoreCount > 0, 1, 0)

#convert NA values to 0s
vcdb_mitre_attack_counts <- vcdb_mitre_attack_counts %>% mutate_all(~replace(., is.na(.), 0))

#calculate percentages for industry types
vcdb_mitre_attack_counts$AccommodationPct <- vcdb_mitre_attack_counts$`industry.Accomodation ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$AdministrativePct <- vcdb_mitre_attack_counts$`industry.Administrative ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$AgriculturePct <- vcdb_mitre_attack_counts$`industry.Agriculture ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$ConstructionPct <- vcdb_mitre_attack_counts$`industry.Construction ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$EducationalPct <- vcdb_mitre_attack_counts$`industry.Educational ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$EntertainmentPct <- vcdb_mitre_attack_counts$`industry.Entertainment ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$FinancePct <- vcdb_mitre_attack_counts$`industry.Finance ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$HealthcarePct <- vcdb_mitre_attack_counts$`industry.Healthcare ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$InformationPct <- vcdb_mitre_attack_counts$`industry.Information ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$ManagementPct <- vcdb_mitre_attack_counts$`industry.Management ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$ManufacturingPct <- vcdb_mitre_attack_counts$`industry.Manufacturing ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$MiningPct <- vcdb_mitre_attack_counts$`industry.Mining ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$OtherServicesPct <- vcdb_mitre_attack_counts$`industry.Other Services ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$ProfessionalPct <- vcdb_mitre_attack_counts$`industry.Professional ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$PublicPct <- vcdb_mitre_attack_counts$`industry.Public ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$RealEstatePct <- vcdb_mitre_attack_counts$`industry.Real Estate ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$RetailPct <- vcdb_mitre_attack_counts$`industry.Retail ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$TradePct <- vcdb_mitre_attack_counts$`industry.Trade ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$TransportationPct <- vcdb_mitre_attack_counts$`industry.Transportation ` / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$UnknownPct <- vcdb_mitre_attack_counts$industry.Unknown / vcdb_mitre_attack_counts$totalCount
vcdb_mitre_attack_counts$UtilitiesPct <- vcdb_mitre_attack_counts$`industry.Utilities ` / vcdb_mitre_attack_counts$totalCount

#write results to csv
write.csv(vcdb_mitre_attack_counts, "vcdb_summary_by_attack_by_year.csv")

#filter out the attack types that are not mapped to D3FEND
vcdb_mitre_attack_counts_defend_mapped <- vcdb_mitre_attack_counts %>% 
    filter(def_tactic_model==1 | def_tactic_harden==1 | def_tactic_detect==1 | def_tactic_isolate==1 | def_tactic_deceive==1 | def_tactic_evict==1 | def_tactic_restore==1) %>%
    arrange(off_tech_id)
#check for whether perfect correlation between Reconnaisance and Resource Development exists (it does)
vcdb_mitre_attack_counts_defend_mapped %>%
    filter((off_tactic_label_Reconnaissance==0 & `off_tactic_label_Resource Development`==1) | (off_tactic_label_Reconnaissance==1 & `off_tactic_label_Resource Development`==0)) %>%
    arrange(off_tech_id)
vcdb_mitre_attack_counts_defend_mapped %>%
    filter((off_tactic_label_Reconnaissance==0 & `off_tactic_label_Resource Development`==1) | (off_tactic_label_Reconnaissance==1 & `off_tactic_label_Resource Development`==0)) %>%
    arrange(off_tech_id)

#display attacks descending by total count -- can see big gap between attacks with 7100 or more total occurrences vs the rest of the attacks
vcdb_mitre_attack_counts_defend_mapped %>% 
    dplyr::select(off_tech_id, off_tech_label, totalCount, def_tactic_model, def_tactic_harden, def_tactic_detect, def_tactic_isolate, def_tactic_deceive, def_tactic_evict, def_tactic_restore) %>% 
    arrange(desc(totalCount))

#check distribution of incident counts and frequencies
library(ggplot2)
hist(round(vcdb_mitre_attack_counts_defend_mapped$totalCount,digits = 3))

#histogram shows three groupings of count rates, so we split the data into 
#these three groups next

#split the data based on distribution (high, medium, and low)
vcdb_mitre_attack_counts_defend_mapped_highCount <- vcdb_mitre_attack_counts_defend_mapped[which(vcdb_mitre_attack_counts_defend_mapped$totalCount > 7000),]
vcdb_mitre_attack_counts_defend_mapped_medCount <- vcdb_mitre_attack_counts_defend_mapped[which(vcdb_mitre_attack_counts_defend_mapped$totalCount < 7000 & vcdb_mitre_attack_counts_defend_mapped$totalCount > 900),]
vcdb_mitre_attack_counts_defend_mapped_lowCount <- vcdb_mitre_attack_counts_defend_mapped[which(vcdb_mitre_attack_counts_defend_mapped$totalCount < 900),]

#histograms to check distributions for each group
#each histogram shows a rough negative binomial distribution
hist(vcdb_mitre_attack_counts_defend_mapped_highCount$totalCount)
hist(vcdb_mitre_attack_counts_defend_mapped_medCount$totalCount)
hist(vcdb_mitre_attack_counts_defend_mapped_lowCount$totalCount)

library(MASS)
library(foreign)

#use negative binomial regression to analyze relationships influencing attack type counts
#with the attacks split by low, medium, and high rates
#using dummy vars for D3FEND tactics instead of counts or frequencies (excluded Reconnaissance and Resource Development because of singularity error)
################################LOW COUNT####################################
summary(nbTotalIncidents <- glm.nb(totalCount ~ def_tactic_model+def_tactic_harden+def_tactic_detect+def_tactic_isolate+def_tactic_deceive+def_tactic_evict+def_tactic_restore+
                                       off_tactic_label_Collection+`off_tactic_label_Command and Control`+`off_tactic_label_Credential Access`+
                                       `off_tactic_label_Defense Evasion`+off_tactic_label_Discovery+off_tactic_label_Execution+off_tactic_label_Exfiltration+
                                       off_tactic_label_Impact+`off_tactic_label_Initial Access`+`off_tactic_label_Lateral Movement`+off_tactic_label_Persistence+
                                       `off_tactic_label_Privilege Escalation`+off_tactic_label_Reconnaissance+`off_tactic_label_Resource Development`, 
                                   data=vcdb_mitre_attack_counts_defend_mapped_lowCount))

################################MEDIUM COUNT####################################
summary(nbTotalIncidents <- glm.nb(totalCount ~ def_tactic_model+def_tactic_harden+def_tactic_detect+def_tactic_isolate+def_tactic_deceive+def_tactic_evict+def_tactic_restore+
                                       off_tactic_label_Collection+`off_tactic_label_Command and Control`+`off_tactic_label_Credential Access`+
                                       `off_tactic_label_Defense Evasion`+off_tactic_label_Discovery+off_tactic_label_Execution+off_tactic_label_Exfiltration+
                                       off_tactic_label_Impact+`off_tactic_label_Initial Access`+`off_tactic_label_Lateral Movement`+off_tactic_label_Persistence+
                                       `off_tactic_label_Privilege Escalation`+off_tactic_label_Reconnaissance+`off_tactic_label_Resource Development`, 
                                   data=vcdb_mitre_attack_counts_defend_mapped_medCount))

################################HIGH COUNT####################################
summary(nbTotalIncidents <- glm.nb(totalCount ~ def_tactic_model+def_tactic_harden+def_tactic_detect+def_tactic_isolate+def_tactic_deceive+def_tactic_evict+def_tactic_restore+
                                       off_tactic_label_Collection+`off_tactic_label_Command and Control`+`off_tactic_label_Credential Access`+
                                       `off_tactic_label_Defense Evasion`+off_tactic_label_Discovery+off_tactic_label_Execution+off_tactic_label_Exfiltration+
                                       off_tactic_label_Impact+`off_tactic_label_Initial Access`+`off_tactic_label_Lateral Movement`+off_tactic_label_Persistence+
                                       `off_tactic_label_Privilege Escalation`+off_tactic_label_Reconnaissance+`off_tactic_label_Resource Development`, 
                                   data=vcdb_mitre_attack_counts_defend_mapped_highCount))

