include("dateTimeFormatter.jl")
include("filter.jl")
include("loader.jl")

using Pkg
Pkg.add("CSV")
Pkg.add("DataFrames")
Pkg.add("Dates")
Pkg.add("Plots")

using Plots
using CSV
using DataFrames
using Dates


df_file_loc = "SWaT_Dataset_Attack_v0_CSV.csv"
df = CSV.File(df_file_loc) |> DataFrame

rename!(df,:" Timestamp" => :"Timestamp")
dates = df[!, :Timestamp]

date_format = DateFormat(" d/m/y H:M:S p") 
datesToDisplay = Dates.DateTime.(dates,date_format)
datesForComparing = Dates.DateTime.(dates,date_format)
datesToDisplay = Dates.Date.(datesToDisplay)
unique!(datesToDisplay)
Dates.Second(datesToDisplay[end] - datesToDisplay[1])

convertedDates = []

for d in dates 
    date = Dates.DateTime.(d,date_format)
    push!(convertedDates, date)
end

p5 = r"50"
p6 = r"60"
p7 = r"Timestamp"
select!(df, Regex(join([p5.pattern,p6.pattern, p7.pattern], "|")))
df_total_rows = nrow(df)
column_names = names(df)

dfMatrix = Matrix(df)

colsToPlot = mapslices(x->[x], dfMatrix, dims=1)[2:end]

fig_y = 17 *5 * ncol(df) * 5
fig_x = 17 * 160 * 7

df_time_start = convert(String, df[1, :]["Timestamp"])
df_time_end = convert(String, df[df_total_rows, :]["Timestamp"])

file_loc = "List_of_attacks_Final.csv"

stages1, anomalies1 = getAnomalies(file_loc)
unique!(anomalies1)

anomalyDates = getAnomalyDatesRange(anomalies1, convertedDates) 
tempDates = convertAnomalyDatesRange(anomalies1, convertedDates)

p = plot(convertedDates, colsToPlot, layout = (17, 1), size = (fig_x, fig_y), xticks = (0:86400:432000, string.(convertedDates)))

for anomaly in anomalies1
    for point in anomaly.attackPoints
        idx = findfirst(x -> x==point, column_names)
        if idx !== nothing
            idxDateStart = findfirst(x-> x == anomaly.timeStart, datesForComparing)
            idxDateEnd = findfirst(x-> x == anomaly.timeEnd, datesForComparing)

            display(plot!(subplot = idx, title = point, convertedDates[idxDateStart:idxDateEnd], colsToPlot[idx][idxDateStart:idxDateEnd], color = "darkred", linewidth=3, thickness_scaling = 1))
        end
    end
end