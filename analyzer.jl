import Pkg

Pkg.add("DataFrames")
Pkg.add("CSV")
Pkg.add("OutlierDetection")
Pkg.add("OutlierDetectionData")
Pkg.add("MLJ")

using DataFrames
using CSV
using MLJ
using OutlierDetection
using OutlierDetectionData: ODDS

mutable struct Pattern
    anomalies::Vector{Any}
    files:: Vector{Any}
    precission:: Int
    window_size:: Int
    attackStages::Vector{Any}
end

function processData(csvFiles, anomalies)

    for file in csvFiles:
        

    networkFile = CSV.File(csvFiles[1]) |> DataFrame
    
    

    return networkFile
end

