include("loader.jl")
include("analyzer.jl")
networkDataLocation = "/Users/nlugi/source/repos/ApisArsi/data/Network"
result_loc = "../output/results.html"
attackListLocation = "/Users/nlugi/source/repos/ApisArsi/List_of_attacks_Final.csv"




csvFiles, table = loadNetworkData(networkDataLocation)

display(csvFiles)
display(table)


stages, anomalies = getAnomalies(attackListLocation)

display(stages)
display(anomalies)

networkFile = processData(csvFiles, anomalies)




