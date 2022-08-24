Parsing PCAP-01-12 Training data

List of files:
- FlowParserTraining.py: Generate flow data from raw data using scapy
- stateful/manage.py: Manage flow dataset
- stateful/ML.py: run legacy classifier to classify DDoS traffic

Dataset processing procedure

- Raw dataset -> Flow dataset -> cleaning dataset -> PerLabel Dataset(unique/not) -> allDataest/mixDataset -> Run classifier

FlowParserTraining.py
- Raw dataset -> Flow dataset

manage.py
- 1 : Flow dataset => clean Dataset: remove flow iD and unnecessary data
- 2 : Clean Flow dataset -> count unique Dataset  (optional)
- 9 : Clean Flow dataset -> genPerlabelDataset(uniqueness): Unique Dataset / non-unique Dataset(all)
- 10: Unique Dataset -> All_unique_Dataset (testing purpose)
- 11: Unique Dataset -> Sampled_Mix_Unique_Dataset (training purpose):
  - 5 s/d 100 (in K -> 5000 - 100000)

ML.py
- Run classifier for DDoS traffic classifier

