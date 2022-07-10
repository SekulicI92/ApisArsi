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

## skipFirst bi trebalo da je 415 recimo, ja sam ostavila 0 jer nemam memorije na kompu, 
## pa imam tipa oko 100 fajlova samo umesto 700 i nesto
## pa da mi ne skipuje nista
## inace skipuje sve logove do trenutka kad su poceli napadi
skipFirst = 0
## ovo se setuje unutar metode na broj fajlova - skipFirst
maxProcess = -1
networkFile = processAll(csvFiles, anomalies, skipFirst, maxProcess)
schema(networkFile)