using Dates

#convert date time to desired format
function dateTime(input)
    input = convert(DateTime, input)
    input = Dates.format(input, "yyyy-mm-dd HH:MM:SS")
    tmp = split(input, " ")

    return [ tmp[1], input]
end