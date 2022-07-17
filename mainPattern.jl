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

## skipFirst bi trebalo da je 415 recimo, ja sam ostavila 0 jer nemam memorije na kompu, 
## pa imam tipa oko 100 fajlova samo umesto 700 i nesto
## pa da mi ne skipuje nista
## inace skipuje sve logove do trenutka kad su poceli napadi
## ovo se setuje unutar metode na broj fajlova - skipFirst

skipFirst = 415
maxProcess = -1
window_size = 100
display(length(loadedAnomalies))
table1, table2, table3 = processAll(csvFiles, loadedAnomalies, skipFirst, maxProcess, window_size)

display(table1)
display(table2)
display(table3)