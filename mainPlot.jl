include("dateTimeFormatter.jl")
include("filter.jl")

using Pkg
# Pkg.add("PyCall")
Pkg.add("CSV")
# Pkg.add("XLSX")
Pkg.add("DataFrames")
Pkg.add("Dates")
Pkg.add("Plots")
# Pkg.add("StatsPlots")
using CSV
# using XLSX
using DataFrames
using Dates
using Plots
# using PyCall
# using StatsPlots
# np = pyimport("numpy")
# dt = pyimport("datetime")

# path = joinpath(pwd(), "SWaT_Dataset_Attack_v0_CSV.csv")
# df = CSV.File(path) |> DataFrame
# rename!(df,:" Timestamp" => :"Timestamp")
# first(df, 10)
# df.Timestamp = Dates.Date.(df.Timestamp |> Array, Dates.DateFormat("m/d/Y")) .+ Dates.Year(2000)
# column_names = names(df)
# namess = union(filter(s->occursin(r"P1", s), column_names), filter(s->occursin(r"101", s), column_names)) 

df_file_loc = "SWaT_Dataset_Attack_v0_CSV.csv"

df = CSV.File(df_file_loc) |> DataFrame

rename!(df,:" Timestamp" => :"Timestamp")
dates = df[!, :Timestamp]

p5 = r"50"
p6 = r"60"
p7 = r"Timestamp"
select!(df, Regex(join([p5.pattern,p6.pattern, p7.pattern], "|")))
df_total_rows = nrow(df)
column_names = names(df)

fig_y = 17 *5 * ncol(df)
fig_x = 17 * 160
plot(layout = (17), size = (fig_x, fig_y))
# date_format = DateFormat(" d/m/y H:M:S p") 
# datesToDisplay = Dates.DateTime.(dates,date_format)
# datesToDisplay = Dates.Date.(datesToDisplay)
# unique!(datesToDisplay)

for (index, col) in enumerate(eachcol(df))
    if index == 1
        continue
    end
    display(plot!(subplot = index-1,
    dates,
    col
    ))
end

# Dataset Start Time and End Time
df_time_start = convert(String, df[1, :]["Timestamp"])
df_time_end = convert(String, df[df_total_rows, :]["Timestamp"])

file_loc = "List_of_attacks_Final.csv"
df = CSV.File(file_loc) |> DataFrame
mutable struct Anomaly
    index::Int
    timeStart::DateTime
    timeEnd::DateTime
    attackPoints::Dict{Any, Any}
    attackStages::Dict{Any, Any}
end

#load anomalies from List of attacks
#returns list of stages/processes and list of anomalies
function anomalies(file_loc)
    stages = Dict{String, Dict}()
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
            attack_points = Dict()
            attack_stages = Dict()
            for i in tmp
                i = strip(i, [' '])
                i = uppercase(i)
                i = replace(i, "-" => "")
                # println(i)
                attack_points[i] = ""
                stage = get_stage(i)
                attack_stages[stage] = ""
                # println(stage)
                if !(stage in keys(stages))
                    stages[stage] = Dict{String, String}()
                end
                stages[stage][i] = ""
            end

            sort!(collect(keys(attack_points)))
            sort!(collect(keys(attack_stages)))
            
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
    # sort fields
    # for key in keys(stages)
    #     stages[key] = collect(keys(stages[key]))
    # end
    sort!(times)
    time_start = times[1]
    time_end = times[end]
    
    print("First anomaly detected $time_start")
    
    # df.reset_index()
    return [ stages, anomalies ]
end

stages1, anomalies1 = anomalies(file_loc)
stages1
anomalies1

# anomaly = anomalies1[4]
# anomaly_idx = range(start = Dates.value(anomaly.timeStart), length = Dates.value(anomaly.timeEnd) - Dates.value(anomaly.timeStart))
# plot!(subplot = 8, anomaly_idx, color="darkred", linewidth=6, alpha=0.8)

#anomaly_idx = anomaly["time_start"] + np.arange(0, int((anomaly["time_end"] - anomaly["time_start"])/time_delta), 1)
# plot!(anomaly_idx, loc, color=color_anomaly, linewidth=6, alpha=0.8)

# time_delta = Dates.Second(1)
