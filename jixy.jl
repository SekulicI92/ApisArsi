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

p5 = r"50"
p6 = r"60"
p7 = r"Timestamp"
select!(df, Regex(join([p5.pattern,p6.pattern, p7.pattern], "|")))
df_total_rows = nrow(df)
column_names = names(df)

dfMatrix = Matrix(df)
colsToPlot = mapslices(x->[x], dfMatrix, dims=1)[2:end]

fig_y = 17 *5 * ncol(df)
fig_x = 17 * 160

plot(datesForComparing, colsToPlot, layout = 17, size = (fig_x, fig_y), xticks = (0:86400:432000, string.(datesToDisplay)))

df_time_start = convert(String, df[1, :]["Timestamp"])
df_time_end = convert(String, df[df_total_rows, :]["Timestamp"])

file_loc = "List_of_attacks_Final.csv"

stages1, anomalies1 = getAnomalies(file_loc)

anomalyDates = getAnomalyDatesRange(anomalies1, datesForComparing)
display(anomalyDates)


plot!(anomalyDates,colsToPlot, layout = 17, size = (fig_x, fig_y), xticks = (0:86400:432000, string.(datesToDisplay)))

