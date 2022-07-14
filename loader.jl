include("filter.jl")


using Pkg
Pkg.add("CSV")
Pkg.add("DataFrames")
Pkg.add("Dates")
using CSV
using DataFrames
using Dates

mutable struct Anomaly
    index::Int
    timeStart::DateTime
    timeEnd::DateTime
    attackPoints::Vector{Any}
    attackStages::Vector{Any}
end


#load anomalies from List of attacks
#returns list of stages/processes and list of anomalies
function getAnomalies(file_loc)
    stages = Dict{String, Vector}()
    anomalies = Anomaly[]
    times = []

    df = CSV.File(file_loc) |> DataFrame

    for (index, row) in enumerate(eachrow(df))
    #    try
            # skip if there is no attack
            try
                tmp = convert(Int, row["Attack #"])
            catch
                continue
            end
            # skip if there is no attack
            attack_point = convert(String, row["Attack Point"])
            attack_point = replace(attack_point, ";" => ",")
            tmp = split(attack_point, ",")
            if row["Attack Point"] == "No Physical Impact Attack"
                continue
            end
            # extract attack start time
            date_format = DateFormat("d/m/y H:M:S") 
            dateTime_start = Dates.DateTime(row["Start Time"],date_format)
            date_start = Dates.Date(dateTime_start)
            time_start = Dates.Time(dateTime_start)

            # extract attack end time
            time_end = row["End Time"]
            dateTime_end = string(date_start, ' ', time_end)
            date_format2 = DateFormat("y-m-d H:M:S") 
            dateTime_end = Dates.DateTime(dateTime_end, date_format2)

            # extract attack points
            attack_points = []
            attack_stages = []
            for i in tmp
                i = strip(i, [' '])
                i = uppercase(i)
                i = replace(i, "-" => "")
                push!(attack_points, i)

                stage = get_stage(i)
                push!(attack_stages, stage)

                if !(stage in keys(stages))
                    stages[stage] = []
                end
                if !(i in stages[stage])
                    push!(stages[stage], i)
                end
            end

            sort!(attack_stages)
            sort!(attack_points)
            
            println("$attack_points, $attack_stages, $dateTime_start, $dateTime_end")

            # define anomaly
            anomaly = Anomaly(
                index,
                dateTime_start,
                dateTime_end,
                attack_points,
                attack_stages,
            )
            
            push!(times, dateTime_start)
            push!(times, dateTime_end)

            push!(anomalies, anomaly)
    #    catch
    #         print("Error: %s" %(str(sys.exc_info())))
    #         print("Row value: %s" %(row))
    #         print("Index: %d" %(index))
    #    end
    end

    sort!(times)
    time_start = times[1]
    time_end = times[end]
    
    print("First anomaly detected $time_start")
    
    # df.reset_index()
   

# #filter anomalies
# filtered_anomalies = []
  
# for anomaly in anomalies
#     for point in anomaly.attackPoints
#         if occursin("50", point) || occursin("60", point)
#             push!(filtered_anomalies, anomaly)
#         end
#     end
# end

return [ stages, unique!(anomalies) ]
end

function loadNetworkData(path)
    """
    load list of files
    """

    csvFiles = []
    total_files = 0
    total_loaded = 0
    total_skipped = 0

    files = readdir(path; join=true)

    for file in files
        total_files += 1

        if contains(file,".csv")
           
            csvFiles = push!(csvFiles, file)
         

            total_loaded += 1
        else
            total_skipped += 1
        end
    end

    files = sort(files)

    table = [
        [ "Total files", total_files],
        [ "Total skipped", total_skipped ],
        ["Loaded" , total_loaded]
    ]

        return  csvFiles, table
end


function getAnomalyDatesRange(anomalies, dates)

    tempDates = Dict{Int, Vector{DateTime}}()
    
    for a in anomalies 
        for d in dates
            if d >= a.timeStart && d <= a.timeEnd
                if !(a.index in keys(tempDates)) 
                    merge!(tempDates, Dict(a.index => []))
                    push!(tempDates[a.index], d)
                else
                    push!(tempDates[a.index], d)
                end
            end
        end
    end

    return tempDates
end

function convertAnomalyDatesRange(anomalies, dates)

    tempDates = Dict{Int, Vector{String}}()
    date_format = DateFormat("dd/mm/yyyy HH:MM:SS p") 
    for a in anomalies 
        for d in dates
            if d >= a.timeStart && d <= a.timeEnd
                if !(a.index in keys(tempDates)) 
                    date = Dates.format(d, date_format)
                    merge!(tempDates, Dict(a.index => String[]))
                    push!(tempDates[a.index], date)
                else
                    date = Dates.format(d, date_format)
                    push!(tempDates[a.index], date)
                end
            end
        end
    end

    return tempDates
end