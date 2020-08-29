require "shellwords"
require "pathname"
require "se_open_data/utils/log_factory"
require "se_open_data/utils/deployment"

module SeOpenData
  class Cli
    # Create a log instance
    Log = SeOpenData::Utils::LogFactory.default

    # Loads the configuration settings, using {SeOpenData::Config#load}.
    # By default no parameters are supplied, so the defaults apply.
    #
    # However, if an environment variable `SEOD_CONFIG` is set, that
    # is used to set the path of the config file.
    #
    # This facility exists is so we can define the variable in cron
    # jobs, to specify different build environments (or "editions" in
    # the old open-data-and-maps terminology).
    #
    # Suggested usage is to use the defaults and allow the
    # `default.conf` (or `local.conf`, if present) to be picked up in
    # development mode (i.e. when `SEOD_CONFIG` is unset), and set
    # `SEOD_CONFIG=prod.conf` for production environments. This allows
    # both of these to be checked in, and for the default case to be
    # development; it also allows developers to have their own
    # environments defined in `local.conf` if they need it (and this
    # won't get checked in if `.gitignore`'ed)
    def self.load_config
      require "se_open_data/config"
      if ENV.has_key? "SEOD_CONFIG"
        # Use this environment variable to define where the config is
        SeOpenData::Config.load ENV["SEOD_CONFIG"]
      else
        SeOpenData::Config.load
      end
    end

    def self.command_run_all
      %w(download convert generate deploy create_w3id triplestore).each do |name|
        puts "Running command #{name}"
        send "command_#{name}".to_sym
      end
    end

    # Removes all the generated files in the directory set by
    # {SeOpenData::Config} value `TOP_OUTPUT_DIR`
    def self.command_clean
      config = load_config
      puts "Deleting #{config.TOP_OUTPUT_DIR} and any contents."
      FileUtils.rm_rf config.TOP_OUTPUT_DIR
    end

    # Obtains new data from limesurvey.
    #
    # Require credentials to be configured.
    # FIXME document more
    def self.command_limesurvey_export
      require "se_open_data/lime_survey_exporter"
      require "se_open_data/utils/password_store"

      config = load_config

      FileUtils.mkdir_p config.SRC_CSV_DIR
      src_file = File.join config.SRC_CSV_DIR, config.ORIGINAL_CSV

      pass = SeOpenData::Utils::PasswordStore.new(use_env_vars: config.USE_ENV_PASSWORDS)
      Log.debug "Checking ENV for passwords" if pass.use_env_vars?
      password = pass.get config.LIMESURVEY_PASSWORD_PATH

      SeOpenData::LimeSurveyExporter.session(
        config.LIMESURVEY_SERVICE_URL,
        config.LIMESURVEY_USER,
        password
      ) do |exporter|
        IO.write src_file, exporter.export_responses(config.LIMESURVEY_SURVEY_ID, "csv", "en")
      end
    end

    # Obtains new data from an HTTP URL
    #
    # The url needs to be configured as DOWNLOAD_URL
    #
    # FIXME document more
    def self.command_http_download
      # Find the config file...
      config = load_config

      # Make the target directory if needed
      FileUtils.mkdir_p config.SRC_CSV_DIR

      # Original src csv file
      original_csv = File.join(config.SRC_CSV_DIR, config.ORIGINAL_CSV)

      # Download the data
      IO.write original_csv, fetch(config.DOWNLOAD_URL)
    end
 
    # Obtains new data by running the `downloader` script in the
    # current directory, if present
    #
    # Does nothing if absent.
    #
    # May require credentials to be configured.
    #
    # Note, although typically we expect the script to be written in
    # Ruby and use the SeOpenData library, we don't assume that and
    # invoke it as a separate process, to allow other languages and
    # tools to be used.
    #
    # The requirements are that:
    #
    # 1. Data is written, in whatever format, to the location named in
    #    the configuration by the value of `ORIGINAL_CSV` in the
    #    directory, relative to the script's directory, named by
    #    `SRC_CSV_DIR`. (It doesn't actually have to be CSV format.)
    #
    # This allows the `converter` script and the rest of the
    # conversion process can then continue to transform the data from
    # here.
    #
    def self.command_download
      downloader_file = File.join(Dir.pwd, "downloader")
      unless File.exist? downloader_file
        Log.warn "no 'downloader' file found in current directory, skipping"
        return
      end
      unless system downloader_file
        raise "'downloader' command in current directory failed"
      end
    end

    # Runs the `converter` script in the current directory, if present
    #
    # Note, although typically we expect the script to be written in
    # Ruby and use the SeOpenData library, we don't assume that and
    # invoke it as a separate process, to allow other languages and
    # tools to be used.
    #
    # The requirements are that:
    #
    # 1. Input data is read from a source, in whatever format, named
    #    in the configuration by the value of `ORIGINAL_CSV` in the
    #    directory, relative to the script's directory, named by
    #    `SRC_CSV_DIR`. (It doesn't actually have to be CSV format.)
    #
    # 2. Output data is written to the expected file, named by the
    #    configured value of `STANDARD_CSV`, in the directory named by
    #    `TOP_OUTPUT_DIR` (again relative to the script's directory).
    #    The file should be a CSV with the schema defined by
    #    {SeOpenData::CSV::Schemas::Latest}.
    #
    # The rest of the conversion process can then continue to
    # transform the data from here.
    #
    def self.command_convert
      converter_file = File.join(Dir.pwd, "converter")
      unless File.exist? converter_file
        raise ArgumentError, "no 'converter' file found in current directory"
      end
      unless system converter_file
        raise "'converter' command in current directory failed"
      end
    end

    # Generates the static data in `WWW_DIR` and `GEN_SPARQL_DIR`
    #
    # Expects data to have been generated by {self.command_convert},
    # as described in the documentation for that method.
    #
    # The static data consists of:
    #
    # - *WWW_DIR*`/doc/` - one .html, .rdf and .ttl file for each
    #   initiative, named after the initiative's identifier field.
    # - *GEN_SPARQL_DIR*`/ - the following files at least:
    #   - `default-graph-uri.txt` - containing the linked-data graph's
    #     default URI
    #   - `endpoint.txt` - containing the URL of a SPARQL end-point
    #     which can be used to query the graph
    #   - `query.rq` - containing a SPARQL query which can be passed to
    #     this end-point that returns a complete list of initiatives
    #
    # Other .rq query files may exist, depending on the application.
    #
    # FIXME what defines the requirements of the data generated by the
    # query?
    def self.command_generate
      require "se_open_data/csv/standard"
      require "se_open_data/initiative/rdf"
      require "se_open_data/initiative/collection"
      config = load_config

      # Delete and re-create an empty WWW_DIR directory.  It's
      # important to start from scratch, to avoid incompletely
      # reflecting config changes (which would happen if we tried to
      # regenerate only those missing files). We don't really want to
      # check timestamps like Make does, because that gets a bit
      # complicated, ignores changes not reflected in the filesystem,
      # e.g. dates, and can't spot spurious junk left in the directory
      # by manual copies etc.
      Log.info "recreating #{config.WWW_DIR}"
      FileUtils.rm_rf config.WWW_DIR
      FileUtils.mkdir_p config.GEN_DOC_DIR # need this subdir

      Log.info "recreating #{config.GEN_SPARQL_DIR}"
      FileUtils.rm_rf config.GEN_SPARQL_DIR
      FileUtils.mkdir_p config.GEN_SPARQL_DIR

      # Copy contents of CSS_SRC_DIR into GEN_CSS_DIR
      FileUtils.cp_r File.join(config.CSS_SRC_DIR, "."), config.GEN_CSS_DIR

      # Find the relative path from GEN_DOC_DIR to GEN_CSS_DIR
      doc_dir = Pathname.new(config.GEN_DOC_DIR)
      css_dir = Pathname.new(config.GEN_CSS_DIR)
      css_rel_dir = css_dir.relative_path_from doc_dir

      # Enumerate the CSS files there, relative to GEN_DOC_DIR
      css_files = Dir.glob(css_rel_dir + "**/*.css", base: config.GEN_DOC_DIR)

      #all
      IO.write config.SPARQL_ENDPOINT_FILE, config.SPARQL_ENDPOINT + "\n"
      IO.write config.SPARQL_GRAPH_NAME_FILE, config.GRAPH_NAME + "\n"

      rdf_config = SeOpenData::Initiative::RDF::Config.new(
        config.GRAPH_NAME,
        config.ESSGLOBAL_URI,
        config.ONE_BIG_FILE_BASENAME,
        config.SPARQL_GET_ALL_FILE,
        css_files,
        nil, #    postcodeunit_cache?
        SeOpenData::CSV::Standard::V1,
        config.SAME_AS_FILE == "" ? nil : config.SAME_AS_FILE,
        config.SAME_AS_HEADERS == "" ? nil : config.SAME_AS_HEADERS,
        config.USING_ICA_ACTIVITIES
      )

      # Load CSV into data structures, for this particular standard
      File.open(config.STANDARD_CSV) do |input|
        input.set_encoding(Encoding::UTF_8)

        collection = SeOpenData::Initiative::Collection.new(rdf_config)
        collection.add_from_csv(input.read)
        collection.serialize_everything(config.GEN_DOC_DIR)
      end
    end

    # Deploys the generated data on a web server.
    #
    def self.command_deploy
      config = load_config
      to_serv = config.respond_to?(:DEPLOYMENT_SERVER) ? config.DEPLOYMENT_SERVER : nil

      deploy(
        to_server: to_serv,
        to_dir: config.DEPLOYMENT_DOC_DIR,
        from_dir: config.GEN_DOC_DIR,
        ensure_present: config.DEPLOYMENT_WEBROOT,
        owner: config.DEPLOYMENT_WEB_USER,
        group: config.DEPLOYMENT_WEB_GROUP,
        verbose: true,
      )
    end

    # This inserts an .htaccess file on the w3id.solidarityeconomy.coop website
    # (strictly, on the server config.DEPLOYMENT_SERVER at config.W3ID_REMOTE_LOCATION)
    def self.command_create_w3id
      config = load_config

      if !config.respond_to? :W3ID_REMOTE_LOCATION
        Log.info "No W3ID_REMOTE_LOCATION configured, skipping"
        return
      end
      
      # Create w3id config
      redir = config.REDIRECT_W3ID_TO

      htaccess = <<-HERE
# Turn off MultiViews
Options -MultiViews +FollowSymLinks

# Directive to ensure *.rdf files served as appropriate content type,
# if not present in main apache config
AddType application/rdf+xml .rdf

# Rewrite engine setup
RewriteEngine On

# Redirect sparql queries for this dataset.
# store1 is where the Virtuoso triplestore is served.
# This is close, but does not work from curl as expected... e.g. with this:
#bombyx:~/SEA/open-data-and-maps/data/dotcoop/domains2018-04-24$ curl -i -L -H \"Accept: application/json\"  --data-urlencode query@generated-data/experimental/sparql/query.rq http://w3id.solidarityeconomy.coop/ica-youth-network/sparql
#RewriteRule ^(sparql)$ http://store1.solidarityeconomy.coop:8890/$1?default-graph-uri=https://w3id.solidarityeconomy.coop/ica-youth-network/ [QSA,R=303,L]

# Redirect https://w3id.org/dotcoop to the appropriate index,
# content negotiation depending on the HTTP Accept header:
RewriteCond %{HTTP_ACCEPT} !application/rdf\+xml.*(text/html|application/xhtml\+xml)
RewriteCond %{HTTP_ACCEPT} text/html [OR]
RewriteCond %{HTTP_ACCEPT} application/xhtml\+xml [OR]
RewriteCond %{HTTP_USER_AGENT} ^Mozilla/.*
RewriteRule ^$ #{redir}index.html [R=303,L]

RewriteCond %{HTTP_ACCEPT} application/rdf\+xml
RewriteRule ^$ #{redir}index.rdf [R=303,L]

RewriteCond %{HTTP_ACCEPT} text/turtle
RewriteRule ^$ #{redir}index.ttl [R=303,L]

# Redirect https://w3id.org/ica-youth-network/X to the appropriate file on data1.solidarityeconomy.coop
# In this case, X will refer to a specific Coop.
# Content negotiation depending on the HTTP Accept header:
RewriteCond %{HTTP_ACCEPT} !application/rdf\+xml.*(text/html|application/xhtml\+xml)
RewriteCond %{HTTP_ACCEPT} text/html [OR]
RewriteCond %{HTTP_ACCEPT} application/xhtml\+xml [OR]
RewriteCond %{HTTP_USER_AGENT} ^Mozilla/.*
RewriteRule ^(.*)$ #{redir}$1.html [R=303,L]

RewriteCond %{HTTP_ACCEPT} application/rdf\+xml
RewriteRule ^(.*)$ #{redir}$1.rdf [R=303,L]

RewriteCond %{HTTP_ACCEPT} text/turtle
RewriteRule ^(.*)$ #{redir}$1.ttl [R=303,L]

# Default rule. Apparently, some older Linked Data applications assume this default (sigh):
RewriteRule ^(.*)$ #{redir}$1.rdf [R=303,L]
HERE

      puts "creating htaccess file.."
      IO.write(config.HTACCESS, htaccess)
      to_serv = config.respond_to?(:DEPLOYMENT_SERVER) ? config.DEPLOYMENT_SERVER : nil

      deploy(
        to_server: to_serv,
        to_dir: File.join(config.W3ID_REMOTE_LOCATION, config.URI_PATH_PREFIX),
        from_dir: config.W3ID_LOCAL_DIR,
        ensure_present: config.W3ID_REMOTE_LOCATION,
        owner: config.DEPLOYMENT_WEB_USER,
        group: config.DEPLOYMENT_WEB_GROUP,
      )
    end

    # Uploads the linked-data graph to the Virtuoso triplestore server
    def self.command_triplestore
      require "se_open_data/utils/password_store"

      config = load_config

      # This gets (encrypted) passwords. Read the documentation in the class.
      pass = SeOpenData::Utils::PasswordStore.new(use_env_vars: config.USE_ENV_PASSWORDS)
      Log.debug "Checking ENV for passwords" if pass.use_env_vars?

      Log.debug "Creating #{config.VIRTUOSO_SCRIPT_LOCAL}"

      content = fetch config.ESSGLOBAL_URI + "vocab/"
      IO.write File.join(config.GEN_VIRTUOSO_DIR, "essglobal_vocab.rdf"), content

      content = fetch config.ESSGLOBAL_URI + "standard/organisational-structure"
      IO.write File.join(config.GEN_VIRTUOSO_DIR, "organisational-structure.skos"), content

      puts "Creating #{config.VIRTUOSO_NAMED_GRAPH_FILE}"
      IO.write config.VIRTUOSO_NAMED_GRAPH_FILE, config.GRAPH_NAME

      puts "Creating #{config.VIRTUOSO_SCRIPT_LOCAL}"
      IO.write config.VIRTUOSO_SCRIPT_LOCAL, <<HERE
SPARQL CLEAR GRAPH '#{config.GRAPH_NAME}';
ld_dir('#{config.VIRTUOSO_DATA_DIR}','*.rdf',NULL);
ld_dir('#{config.VIRTUOSO_DATA_DIR}','*.skos',NULL);
rdf_loader_run();
HERE

      to_serv = config.respond_to?(:VIRTUOSO_SERVER) ? config.VIRTUOSO_SERVER : nil
      deploy(
        to_server: to_serv,
        to_dir: config.VIRTUOSO_DATA_DIR,
        from_dir: config.GEN_VIRTUOSO_DIR,
        ensure_present: config.VIRTUOSO_ROOT_DATA_DIR,
        owner: config.VIRTUOSO_USER,
        group: config.VIRTUOSO_GROUP,
      )

      if (config.AUTO_LOAD_TRIPLETS)
        password = pass.get config.VIRTUOSO_PASS_FILE
        puts autoload_cmd "<PASSWORD>", config
        unless system autoload_cmd password, config
          raise "autoload triplets failed"
        end
      else
        puts <<HERE
****
**** IMPORTANT! ****
**** The final step is to load the data into Virtuoso with graph named #{config.GRAPH_NAME}.
**** Execute the following command, providing the password for the Virtuoso dba user:
****\t#{autoload_cmd "<PASSWORD>", config}
HERE
      end
    rescue
      # Delete this output file, and rethrow
      File.delete config.VIRTUOSO_SCRIPT_LOCAL if File.exist? config.VIRTUOSO_SCRIPT_LOCAL
      raise
    end

    # Gets the content of an URL, following redirects
    #
    # Also sets the 'Accept: application/rdf+xml' header.
    #
    # @return the query content
    def self.fetch(uri_str, limit = 10)
      require "net/http"
      raise ArgumentError, "too many HTTP redirects" if limit == 0

      uri = URI(uri_str)
      request = Net::HTTP::Get.new(uri)
      request["Accept"] = "application/rdf+xml"

      puts "fetching #{uri}"
      response = Net::HTTP.start(
        uri.hostname, uri.port,
        :use_ssl => uri.scheme == "https",
      ) do |http|
        http.request(request)
      end

      case response
      when Net::HTTPSuccess
        response.body
      when Net::HTTPRedirection
        location = response["location"]
        warn "redirected to #{location}"
        fetch(location, limit - 1)
      else
        response.value
      end
    end
    
    private

    # generates the autoload command, with the given password
    def self.autoload_cmd(pass, config)
      isql = <<-HERE
isql-vt localhost dba "#{esc pass}" "#{esc config.VIRTUOSO_SCRIPT_REMOTE}"
HERE
      if !config.respond_to? :VIRTUOSO_SERVER
        return isql
      end

      return <<-HERE
ssh -T "#{esc config.VIRTUOSO_SERVER}" "#{esc isql.chomp}"
HERE
    end

    # escape double quotes in a string
    def self.esc(string)
      string.gsub('"', '\\"').gsub('\\', '\\\\')
    end

    # Delegates to Deployment#deploy
    def self.deploy(**args)
      SeOpenData::Utils::Deployment.new.deploy(**args)
    end

  end
end
