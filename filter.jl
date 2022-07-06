#extract process/stage number from input string (MV101 => 1)
function get_stage(input)
    number = ' '
    for i in input
        if i in ('1', '2', '3', '4', '5', '6')
            number = i
            break
        end
    end
    return string('P', number)
end

#extract time from anomalies based on filter
function get_times(anomalies, filter_by=None)
    times = []

    filter_tag = ""
    if type(filter_by) == list
        filter_by.sort()
        filter_tag = "_".join(filter_by)
    end

    filtered_anomalies = []
    for anomaly in anomalies
        is_hit = False
        if filter_by == None
            is_hit = True
        else
            if type(filter_by) == list
                tag = "_".join(anomaly["attack_points"])
                if filter_tag == tag
                    is_hit = True
                end
            else
                if filter_by in anomaly["attack_stages"]
                    is_hit = True
                end
                if filter_by in anomaly["attack_points"]
                    is_hit = True
                end
            end
        end

        if is_hit
            time_start = anomaly["time_start"]
            time_end = anomaly["time_end"]
            times.append(np.array(time_start, dtype=np.datetime64))
            times.append(np.array(time_end, dtype=np.datetime64))

            filtered_anomalies.append(anomaly)
        end
    end
    times.sort()
    time_start = times[0]
    time_end = times[len(times)-1]

    return [ time_start, time_end, filtered_anomalies ]
end