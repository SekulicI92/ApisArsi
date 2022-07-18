include("loader.jl")
include("analyzer.jl")
networkDataLocation = "data/Network"
result_loc = "../output/results.html"
attackListLocation = "List_of_attacks_Final.csv"


csvFiles, table = loadNetworkData(networkDataLocation)
display(csvFiles)
display(table)


stages, loadedAnomalies = getAnomalies(attackListLocation)
display(stages)
display(loadedAnomalies)

skipFirst = 415
maxProcess = -1
windowSize = 100
display(length(loadedAnomalies))
table1, table2, table3 = processAll(csvFiles, loadedAnomalies, skipFirst, maxProcess, windowSize)

display(table1)
display(table2)
display(table3)