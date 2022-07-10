import Pkg

Pkg.add("DataFrames")
Pkg.add("CSV")
using DataFrames
using CSV

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
    precission:: Int
    detection::Dict{Int, Vector{Detection}}
    header::Vector{Any}
    #ref_tc::threading_control.threading_control(max_work=3600*12, max_threads=20)
end

mutable struct TotalStats
    rows::Int
    anomalies::Int
    stages::Int
    attackPoints::Int
    attackStages::Int
end

pattern = Pattern(
    [],
    Dict{String, Vector{Stats}}(),
    Dict{String, Vector{Any}}(),
    100,
    100,
    Dict{Int, Vector{Detection}}(),
    []
)

totalStats = TotalStats(0, 0, 0, 0, 0)

anomalies_unique = []
stages_unique = []

function processAll(csvFiles, anomalies, skipFirst, maxProcess)
    pattern.files = csvFiles

    for anomaly in anomalies
        ## time_start and time_end are of DateTime type and in format: "d/m/y H:M:S"
        ## tako su sacuvano u anomaly objektu, tako da sam zaobisla Dusanov normalize
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

    ## sluze samo za statistiku, ispisuju se dole u petlji
    iterator = 0
    total_processed = 0

    ## setovanje max broja procesa, tj broja threadova
    if maxProcess == -1
        maxProcess = length(pattern.files) - skipFirst
    end

    # iterate file by file
    for file in pattern.files
        iterator += 1
        if skipFirst > -1 && iterator < skipFirst
            continue
        end

        if maxProcess > -1 && total_processed >= maxProcess
            break
        end

        println("$(total_processed+1) / $maxProcess | $iterator / $(length(pattern.files)) processing file $file")

        ## tebi sam ostavila threadove :)

        # self.ref_tc.wait_threads()
        # self.ref_tc.inc_threads()

        # if self.header == None:
        #     df = pd.read_csv(file)
        #     self.header = df.columns.tolist()

        # thread.start_new_thread(self.process, (file,))
        total_processed += 1
    end

    # while self.ref_tc.get_total_threads() > 0 and self.ref_tc.can_work():
    #     time.sleep(0.3)


    ## statistika - table1 je broj i lista attack point-a i attack stage-ova
    totalStats.attackPoints = length(anomalies_unique)
    totalStats.attackStages = length(stages_unique)

    attack_points = join(anomalies_unique, ", ")
    attack_stages = join(stages_unique, ", ")

    table1 = [
        [ "# rows",  "# Attack points", "Attack points", "# Attacked stages", "Attacked stages" ],
        [ totalStats.rows, totalStats.attackPoints, attack_points, totalStats.attackStages, attack_stages]
    ]        

    ## malo smislenija statistika - detektovani, promaseni, isto to za network tipove, false positives
    table2 = [
        [ "Attack #", "Detected", "Missed", "Attack Type", "Detected network requests",  "Missed network requests", "False positive network requests" ],
    ]

    ## ovo sam sve samo prepakovala na Julia-u, ne mogu da testiram nista bez process metode
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

    stats_sorted = []
    for index in keys(pattern.detection)
        if pattern.detection[index].attackType != "Network"
            continue
        end
        ## ne radi mi vise mozak, ne kontam sto ovde appenduje niz vrednosti, 
        ## ne znam jel ja treba da uradim push! u stats_sorted il sta
        # stats_sorted.append([
        #     index,
        #     self.detection[index]["detected"],
        #     self.detection[index]["missed"],
        #     self.detection[index]["attack_type"],
        #     self.detection[index]["detected_network_requests"],
        #     self.detection[index]["missed_network_requests"],
        #     self.detection[index]["false_positive_network_requests"],
        # ])
    end
            
    # stats_sorted = sorted(stats_sorted, key=lambda x: x[0])
    # for s in stats_sorted:
    #     if s[0] == 0:
    #         s[0] = "*"
    #     table2.append(s)



    # stats for network requests
    total = 0
    detected = 0 
    missed = 0
    false_positive = 0
    for index in keys(pattern.detection)
        if pattern.detection[index].attackType != "Network"
            continue
        end

        total += self.detection[index].detectedNetworkReq
        detected += self.detection[index].detectedNetworkReq
    
        total += self.detection[index].missedNetworkReq
        missed += self.detection[index].missedNetworkReq

        total += self.detection[index].falsePositiveNetworkReq
        false_positive += self.detection[index].falsePositiveNetworkReq
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

    ## treba naci kako se formatira float, ako je uopste neophodno
    # detection_rate = "%.2f" %(detection_rate)
    # miss_rate = "%.2f" %(miss_rate)
    # false_positive_rate = "%.2f" %(false_positive_rate)

    table3 = [
        [ "Total", "Detected", "Detection %", "Missed", "Miss %", "False Positive", "False Positive %" ],
        [ total, detected, detection_rate, missed, miss_rate, false_positive, false_positive_rate ],
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

    # detection_rate = "%.2f" %(detection_rate)
    # miss_rate = "%.2f" %(miss_rate)

    table4 = [
        [ "Total", "Detected", "Detection %", "Missed", "Miss %" ],
        [ total, detected, detection_rate, missed, miss_rate ],
    ]

    return [ table1, table2, table3, table4 ]

    # networkFile = nothing
    # for file in csvFiles
    #     networkFile = CSV.File(file) |> DataFrame
    # end
    # return networkFile
end



