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


t = plot(dates, colsToPlot, layout = 17, size = (fig_x, fig_y), xticks = (0:86400:432000, string.(datesToDisplay)))
display(t)


df_time_start = convert(String, df[1, :]["Timestamp"])
df_time_end = convert(String, df[df_total_rows, :]["Timestamp"])

file_loc = "List_of_attacks_Final.csv"

stages1, anomalies1 = getAnomalies(file_loc)
unique!(anomalies1)

anomalyDates = getAnomalyDatesRange(anomalies1, datesForComparing) 
tempDates = convertAnomalyDatesRange(anomalies1, datesForComparing)

display(tempDates)

for anomaly in anomalies1
        for point in anomaly.attackPoints
            idx = findfirst(x -> x==point, column_names)
  
            if idx !== nothing
                idxDateStart = findfirst(x-> x == anomaly.timeStart, datesForComparing)
                idxDateEnd = findfirst(x-> x == anomaly.timeEnd, datesForComparing)

            
                #trebalo bi izvuci vrednosti kolone koja je attack point u redovima kad se desava anomalija
                #idxDateStart i idxDateEnd bi trebalo da vrate taj index
                #ali iz nekog razloga nmg da skontam kako da izvucem taj niz vrednosti
                forPlot = dfMatrix[idxDateStart:1:idxDateEnd][idx]
              
                #display(plot!(tempDates[anomaly.index], forPlot, color = "darkred"))

                #i onda bi trebalo da moze plotovati
            end
        end
    end
#t2 = plot!(tmpDates, colsToPlot, layout = 17, size = (fig_x, fig_y))
#display(t2)
