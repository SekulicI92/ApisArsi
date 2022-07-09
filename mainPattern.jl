include("loader.jl")
include("analyzer.jl")
networkDataLocation = "data/Network"
result_loc = "../output/results.html"
attackListLocation = "List_of_attacks_Final.csv"




csvFiles, table = loadNetworkData(networkDataLocation)

display(csvFiles)
display(table)


stages, anomalies = getAnomalies(attackListLocation)

display(stages)
display(anomalies)

networkFile = processData(csvFiles, anomalies)
schema(networkFile)



