import Pkg

Pkg.add("DataFrames")
Pkg.add("CSV")
Pkg.add("BitIntegers")
Pkg.add("Statistics")

using DataFrames
using CSV
using BitIntegers
using Statistics


mutable struct Stats
    index::Int
    anomalies::Vector{Anomaly}
    timeStart::DateTime
    timeEnd::DateTime
end

mutable struct Detection
    detected::Bool
    missed::Bool
    falsePositive::Bool
    attackType::String
    detectedNetworkReq::Int
    missedNetworkReq::Int
    falsePositiveNetworkReq::Int
end

mutable struct Pattern
    files:: Vector{Any}
    stats::Dict{String, Stats}
    windows::Dict{String, Vector{Any}}
    window_size:: Int
    precision:: Int
    detection::Dict{Int, Detection}
    headers::Vector{Any}
    alerts::Vector{Any}
end

mutable struct TotalStats
    rows::Int
    anomalies::Int
    stages::Int
    attackPoints::Int
    attackStages::Int
end

totalStats = TotalStats(0, 0, 0, 0, 0)

anomalies_unique = []
stages_unique = []
window_size = 100
maxThreads = 6

pattern = Pattern(
    [],
    Dict{String, Vector{Stats}}(),
    Dict{String, Vector{Any}}(),
    100,
    5,
    Dict{Int, Detection}(),
    [],
    []
)

function processAll(csvFiles, anomalies, skipFirst, maxProcess, windowSize)
    pattern.files = csvFiles
    headers = []
    threads = []
    window_size = windowSize

    for anomaly in anomalies
        ## time_start and time_end are of DateTime type and in format: "d/m/y H:M:S"
        time_start = anomaly.timeStart
        time_end = anomaly.timeEnd
        tag = string(time_start, "_", time_end)

        if !(tag in keys(pattern.stats))
            pattern.stats[tag] = Stats(
                anomaly.index,
                [],
                time_start,
                time_end
            )
        end
        push!(pattern.stats[tag].anomalies, anomaly)
    end

    iterator = 0
    total_processed = 0

    if maxProcess == -1
        maxProcess = length(pattern.files) - skipFirst
    end

    i = 0
    activeThreads = 0

    # iterate file by file
    for file in pattern.files
        iterator += 1
        i += 1
        if skipFirst > -1 && iterator < skipFirst
            continue
        end

        if maxProcess > -1 && total_processed >= maxProcess
            break
        end

        println("$(total_processed+1) / $maxProcess | $iterator / $(length(pattern.files)) processing file $file")

        if length(headers) == 0
            df = CSV.File(file) |> DataFrame
            pattern.headers = names(df)
        end
 
        while (activeThreads >= maxThreads)
            i = 0
            for t in threads
                i += 1
                if (istaskdone(t))              
                    deleteat!(threads, i)
                    activeThreads -= 1
                end
            end
        end

        sleep(0.3)
        t = Base.Threads.@spawn processFile!(file, skipFirst, anomalies)
        activeThreads += 1
        push!(threads, t)

        # processFile!(file, pattern.precision, anomalies)
        total_processed += 1
    end

    while (length(threads) > 0)
        i = 0
        for t in threads
            i += 1
            if (istaskdone(t))
                deleteat!(threads, i)
            end
        end
    end

    totalStats.attackPoints = length(unique!(anomalies_unique))
    totalStats.attackStages = length(unique!(stages_unique))

    attack_points = join(unique!(anomalies_unique), ", ")
    attack_stages = join(unique!(stages_unique), ", ")

    table1 = [
        [ "# rows",  "# Attack points", "Attack points", "# Attacked stages", "Attacked stages" ],
        [ totalStats.rows, totalStats.attackPoints, attack_points, totalStats.attackStages, attack_stages]
    ]        

    for index in keys(pattern.detection)
        if pattern.detection[index].detectedNetworkReq > 0
            pattern.detection[index].detected = true
        elseif pattern.detection[index].missedNetworkReq > 0
            pattern.detection[index].missed = true
        elseif pattern.detection[index].falsePositiveNetworkReq > 0
            pattern.detection[index].falsePositive = true
        end

        pattern.detection[index].attackType = "Network"
        if pattern.detection[index].detected == false && pattern.detection[index].missed == false
            pattern.detection[index].attackType = "Physical"
        end
        if pattern.detection[index].falsePositive > 0
            pattern.detection[index].attackType = "Network"
        end
    end

    # stats for network requests
    total = 0
    detected = 0 
    missed = 0
    false_positive = 0
    for index in keys(pattern.detection)
        if pattern.detection[index].attackType != "Network"
            continue
        end

        total += pattern.detection[index].detectedNetworkReq
        detected += pattern.detection[index].detectedNetworkReq
    
        total += pattern.detection[index].missedNetworkReq
        missed += pattern.detection[index].missedNetworkReq

        false_positive += pattern.detection[index].falsePositiveNetworkReq
    end

    detection_rate = 0
    if detected > 0 && total > 0
        detection_rate = detected * 100.0 / total 
    end

    miss_rate = 0
    if missed > 0 && total > 0
        miss_rate = missed * 100.0 / total 
    end

    false_positive_rate = 0
    if false_positive > 0 && total > 0
        false_positive_rate = false_positive * 100.0 / total 
    end

    table2 = [
        [ "Total", "Detected", "Detection %", "Missed", "Miss %"],
        [ total, detected, detection_rate, missed, miss_rate],
    ]

    # stats for detection of anomalies
    total = 0
    detected = 0 
    missed = 0
    
    for index in keys(pattern.detection)
        if index == 0
            continue
        end

        if pattern.detection[index].attackType != "Network"
            continue
        end
                    
        if pattern.detection[index].detected
            total += 1
            detected += 1
        else
            total += 1
            missed += 1
        end
    end

    detection_rate = 0
    if detected > 0 && total > 0
        detection_rate = detected * 100.0 / total 
    end

    miss_rate = 0
    if missed > 0 && total > 0
        miss_rate = missed * 100.0 / total 
    end

    table3 = [
        [ "Total", "Detected", "Detection %", "Missed", "Miss %" ],
        [ total, detected, detection_rate, missed, miss_rate ],
    ]

    return [ table1, table2, table3 ]
end

function processFile!(file, precision, anomalies)

    it = 0
    df = CSV.File(file) |> DataFrame

    for (index, row) in enumerate(eachrow(df))
        
        it += 1

        if it % precision != 0
            continue
        end

        date = string(row["date"])

        day = ""
        month = ""
        year = ""

        if contains(date, "-")
            day = tryparse(Int32, SubString(date, 1, 2))
            if day === nothing
                day = parse(Int32, date[1])
                month = SubString(date, 3, 5)
                year = parse(Int32, SubString(date, 7, 8)) + 2000
            else  
                month = SubString(date, 4, 6)
                year = parse(Int32,SubString(date, 8, 9)) + 2000
            end
        else
            day = tryparse(Int32, SubString(date, 1, 2))
            if day === nothing
                day = parse(Int32, date[1])
                month = SubString(date, 2, 4)
                year = parse(Int32, SubString(date, 5, 8))
            else
                month = SubString(date, 3, 5)
                year = parse(Int32,SubString(date, 6, 9))
            end
        end
        if ( month == "Dec") 
                month = 12
        elseif (month == "Nov")
                month = 11
        elseif (month == "Sep")
                month = 9
        elseif (month == "Aug")
                month = 8
        elseif (month == "Jul")
                month = 7
        elseif (month == "Jun")
                month = 6
        elseif (month == "May")
                month = 5
        elseif (month == "Apr")
                month = 4
        elseif (month == "Mar")
                month = 3
        elseif (month == "Feb")
                month = 2
        elseif (month == "Jan")
                month = 1       
        end

        date = Dates.Date(year, month, day)
        time = Dates.Time(string(row["time"]), "HH:MM:SS")
        date_time = Dates.DateTime(date, time)

        anomaliesByTimestamp = getAnomaliesByTimestamp!(date_time, anomalies)   
        
        for anomaly in anomaliesByTimestamp
            for attack_point in anomaly.attackPoints
                push!(anomalies_unique, attack_point)
            end 

            for attack_stage in anomaly.attackStages
                push!(stages_unique, attack_stage)
            end
        end

        modbusFunctionDescription = contains(string(row["Modbus_Function_Description"]), "Response")

        if !modbusFunctionDescription
            continue
        end

        totalStats.rows += 1

        value = 0     
        modbusValue = split(string(row["Modbus_Value"]), ";")

        modbusValue = modbusValue[1]
        modbusValue = replace(modbusValue, "0x" => "")
        modbusValue = replace(modbusValue, " " => "")
        fixedMbValue = "0x" * modbusValue

        if length(modbusValue) != 8
            continue
        end

        temp = chop(fixedMbValue, head=0, tail = 6)
        value = tryparse(Float64, temp)

        ongoingAttack = false
        if(length(anomaliesByTimestamp) > 0)
            ongoingAttack = true
        end

        destination = string(row["SCADA_Tag"])
        destination = replace(destination, "HMI_" => "")

        moving_window!(destination, value)

        for anomaly in anomaliesByTimestamp
            index = anomaly.index

            flag = index in keys(pattern.detection)
      
            if (flag) 
                detection = pattern.detection[index]
            else 
                detection = Detection(
                    false,
                    false,
                    false,
                    "2" ,
                    0,
                    0,
                    0,
                )
                merge!(pattern.detection, Dict(index => detection))
            end

            isOk = false
    
            for attackPoint in anomaly.attackPoints
                if attackPoint == destination
                    isOk = true  
                    break  
                end
            end
            
            if isOk == false
                continue
            end

            isAttackDetected = detectAttack!(destination)

            if ongoingAttack == true
            
                if isAttackDetected == true
                    pattern.detection[index].detectedNetworkReq += 1
                else
                    pattern.detection[index].missedNetworkReq += 1
                end
            end
        end
    
        if length(anomaliesByTimestamp) == 0
           
            isAttackDetected = detectAttack!(destination)
            if isAttackDetected == false
                continue
            else
       
                flag = 1 in keys(pattern.detection)

                if (!flag)
                dt = Detection(
                  false,
                  false,
                  false,
                  "2" ,
                  0,
                  0,
                  0,
                )
                merge!(pattern.detection, Dict(1 => dt))
          
                end

            pattern.detection[1].falsePositiveNetworkReq += 1
            end
        end
    end

    return true
end

function from_hex(h, n)
    b = hex2bytes(h)
    for x in b
        n <<= 8
        n |= x
    end
    return n
end


function detectAttack!(name)

if length(pattern.windows[name]) < window_size
    return false
end

stdev = std(pattern.windows[name])
average = median(pattern.windows[name])

min_border = average - stdev
max_border = average + stdev

empty!(pattern.alerts)

for idx in range(1, length(pattern.windows[name])-1)
    value = pattern.windows[name][idx]

    isForAlert = false
    if value < min_border
        isForAlert = true
    end

    if value > max_border
        isForAlert = true
    end

    if isForAlert

        push!(pattern.alerts, idx)
    end       
end

# minimum 10% of window size must be detection rate
minAlerts = window_size/100*10 
maxAlerts = window_size/100*45 

flag = true

if length(pattern.alerts) > minAlerts && length(pattern.alerts) < maxAlerts
    #println("alerts = $(length(pattern.alerts)) minAlerts =  $minAlerts maxAlerts = $maxAlerts")
    flag = true
else
    #println("alerts = $(length(pattern.alerts)) minAlerts =  $minAlerts maxAlerts = $maxAlerts")
    flag = false
end
    return flag
end


function moving_window!(name, value)
    
    if name in keys(pattern.windows)
    else
        temp = Dict{String, Vector{Int}}(name => [])
        merge!(pattern.windows, temp)
    end

    if length(pattern.windows[name]) > window_size
        pattern.windows[name] = pattern.windows[name][2:end]
    end

    push!(pattern.windows[name],value)

end


function getAnomaliesByTimestamp!(date_time, anomalies)
        
        res = []

        for anomaly in anomalies
            if (date_time >= anomaly.timeStart && date_time <= anomaly.timeEnd ) 
                push!(res,anomaly)
            end
        end

    return res
end