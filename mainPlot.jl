include("dateTimeFormatter.jl")
include("filter.jl")

using Pkg
Pkg.add("PyCall")
Pkg.add("CSV")
Pkg.add("XLSX")
Pkg.add("DataFrames")
Pkg.add("Dates")
Pkg.add("Plots")
using CSV
using XLSX
using DataFrames
using Dates
using Plots
using PyCall
np = pyimport("numpy")
dt = pyimport("datetime")

# path = joinpath(pwd(), "SWaT_Dataset_Attack_v0_CSV.csv")
# df = CSV.File(path) |> DataFrame
# rename!(df,:" Timestamp" => :"Timestamp")
# first(df, 10)
# select!(df, r"101")
# df.Timestamp = Dates.Date.(df.Timestamp |> Array, Dates.DateFormat("m/d/Y")) .+ Dates.Year(2000)
# column_names = names(df)
# namess = union(filter(s->occursin(r"P1", s), column_names), filter(s->occursin(r"101", s), column_names)) 

df_file_loc = "SWaT_Dataset_Attack_v0_CSV.csv"

df = CSV.File(df_file_loc) |> DataFrame
rename!(df,:" Timestamp" => :"Timestamp")
df_total_rows = nrow(df)

plot(
    df[!, :Timestamp],
    df[!, :FIT101],
    title = "FIT101",
    xlabel = "Date&time",
    ylabel = "Value",
    legend = :topleft,
)

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

time_delta = Dates.Second(1)
# time_start, time_end, filtered_anomalies = filter.get_times(anomalies, None)

# time_start -= 300
# time_end += 300

# time_len = int((time_end - time_start) / time_delta)

# x = time_start + np.arange(0, time_len, 1)
# idx_start = int((time_start - df_time_start) / time_delta)
# idx_end = int((time_end - df_time_start) / time_delta)

# # remove old
# output_dir = "../output"
# file_loc = os.path.join(output_dir, "all.png")
# os.remove(file_loc)

# obj = {
#     "log_prefix": "",
#     "name": "all",
#     "file_loc": "../output/all.png", 
#     "df": df, 
#     "time_start": time_start, 
#     "time_delta": time_delta, 
#     "idx_start": idx_start, 
#     "idx_end": idx_end,
#     "filtered_anomalies": filtered_anomalies,
#     # "title": "All stages together",
#     "title": "",
#     "x": x
# }
# plot.process(obj)

# plot(
#     df[df["Country/Region"] .== "US", :Date],
#     df[df["Country/Region"] .== "US", :Cases],
#     title = "Confirmed cases US",
#     xlabel = "Date",
#     ylabel = "Number of cases",
#     legend = false,
# )