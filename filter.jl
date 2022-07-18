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