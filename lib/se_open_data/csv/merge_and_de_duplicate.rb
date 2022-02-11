# coding: utf-8
require "csv"
require "levenshtein"

module SeOpenData
  module CSV
    MAX_DIST = 4
    NAME_FIELD = "Name"

    # @param array - array to find the matches for
    # @param dist - the levenshtein distance to check for
    # @returns - an array of matches (in the form of [[match,match],[match,match],[match]])
    # go through the array for each element and make a matched array, after that remove all matched from array and repeat
    def self.get_all_levinshtein_matches(keys, dist)
      kcopy = keys
      kmatches = []
      keys.each { |k|
        kmatch = []
        kcopy.each { |kc|
          kmatch += [kc] if Levenshtein.distance(k, kc) < dist
        }
        next if kmatch == []
        kcopy -= kmatch
        kmatches.push(kmatch)
        break if kcopy.length == 0
      }
      return kmatches
    end

    def self.mk_duplicate_by_ids(domainHeader, keys, csv_in)
      headers = nil
      duplicate_by_ids = {}
      csv_in.each do |row|
        key = keys.map { |k| row[k] }

        unless headers
          headers = row.headers
        end

        if duplicate_by_ids.has_key?(key)
          duplicate_by_ids[key].push(row)
        else
          duplicate_by_ids[key] = [row]
        end
      end

      return [duplicate_by_ids, headers]
    end

    # Make an index of the input data
    #
    # The first returned value is the csv_map: a hash of primary keys
    # from the data (an array of strings taken from the fields named
    # in keys) to the respective CSV row as a hash. One of these hash
    # entries, defined by domainHeader, is a string which should
    # contain a delimited list of domains (represented as HTTP(S)
    # URLs)
    #
    # The second is the name_map: a hash mapping normalised registrant
    # names to concatenated lists of selected field values, also
    # normalised, back to the primary key source row's primary key.
    #
    # The third is the duplicate_by_ids: a hash mapping primary keys
    # to a list of CSV rows (as hashes) having that key.
    #
    # The last is a list of CSV header field names
    def self.mk_csv_map_etc(domainHeader, duplicate_by_ids, keys)
      small_words = %w(on the and ltd limited llp community SCCL)
      small_word_regex = /\b#{small_words.map { |w| w.upcase }.join("|")}\b/
            
      name_map = {}
      csv_map = {}
      duplicate_by_ids.each_pair do |key, rows|
        rows.each do |row|
          fields_key = ""
          name = row.field(NAME_FIELD)
          
          #mix fields and make a key
          #if matches that means that entry is a duplicate
          row.headers.each do |head|
            unless head == domainHeader || keys.include?(head) || row.field(head) == nil || head == NAME_FIELD
              fields_key += row.field(head)
            end
          end
          
          fields_key.tr!("^A-Za-z0-9", "")
          fields_key.upcase!
          
          name = name.to_s.
                   gsub(/\s/, "").
                   upcase.
                   gsub(small_word_regex, "").
                   sub(/\([[:alpha:]]*\)/, "").
                   gsub(/[[:punct:]]/, "").
                   sub(/COOPERATIVE/, "COOP").
                   sub("SCCL", "")
          
          #map name => (map fields_key => set of key)
          #order them by name
          # Remove key from field_map as it was already found as a duplicate
          unless csv_map.has_key?(key) && !csv_map[key][domainHeader].include?(row.field(domainHeader))
            if !name_map.has_key? name
              name_map[name] = { fields_key => [key] }
            else
              
              # name_map[name].push(key)
              # build up field_map
              if !name_map[name].has_key? fields_key
                #here
                name_map[name][fields_key] = [key]
              else
                name_map[name][fields_key].push(key)
              end
            end
          end
          
          add_to_csv_map(domainHeader, csv_map, key, row)
        end
      end
      
      return [csv_map, name_map]
    end
      
    def self.add_to_csv_map(domainHeader, csv_map, key, row)

      # If the key is already being used, add the domain to the existing domain.
      if csv_map.has_key? key
        domain = row.field(domainHeader)
        existingDomain = csv_map[key][domainHeader]
        if !existingDomain.include?(domain)
          csv_map[key][domainHeader] += SeOpenData::CSV::Standard::V1::SubFieldSeparator + domain
        end
      # csv_err << row
      else
        # csv_out << row
        csv_map[key] = row.to_h
      end
    end
    
  
    def self.munge_name_map(name_map)
      
#      $stderr.puts(name_map.keys)
      #name_map groups them by name
      #merge entries (in csv_map) that have the same name, and a leivenstein distance of < 2
      field_map = {}
      name_map.each { |name, val|
        #for each mapping check the distance between the keys
        # returns [[match,match],[match,match],[match]] structure
        matched_keys = get_all_levinshtein_matches(name_map[name].keys, MAX_DIST)
        # buiname_mapld up field_map
        #if there are matched keys that means we have to merge them
        #i.e. add all of the entries to one of them
        if !matched_keys.empty?
          matched_keys.each { |matched|
            first_key = matched.first
            matched.each { |key|
              unless key == first_key
                # merge
                name_map[name][first_key] = name_map[name][first_key] + name_map[name][key]
                # remove
                name_map[name].reject! { |k, v| k == key }
              end
            }
          }
        end
      }
      #flatten name_map
      name_map.each { |name, fieldskey|
        fieldskey.each { |fkey, keys|
          str_key = name + fkey
          field_map[str_key] = keys
        }
      }

      return field_map
    end


    def self.mk_addr_csv_original(original_csv, csv_opts, keys)
      csvorig = nil
      csvorig = ::CSV.read(original_csv, **csv_opts) if original_csv != nil
      
       # This seems to build a copy of the original csv in a hash addr_csv_original
      # keyed by the unique identifiers of the original data

      addr_csv_original = {}
      if csvorig
        csvorig.each do |row|
          key = keys.map { |k| row[k] }
          addr_csv_original[key] = row.to_h
        end
      end

      return addr_csv_original
    end

    def self.mk_duplicate_by_fields(domainHeader, field_map, csv_map)
      duplicate_by_fields = []
      field_map.each do |hash, values|
        #skip if no duplicates to merge
        next unless values.length > 1
        duplicate_by_fields.push(values)
        # merge domains into the first found duplicate
        # and remove all duplicate rows
        first = values.first
        values.drop(1).each do |dup|
          # add domain to the first entry (only it doesn't exist already)
          registrant = csv_map[dup]
          unless registrant
            #pp csv_map
            pp [hash, values]
            pp field_map
            throw "Can't find match for registrant ID #{dup}: Index csv_map[#{dup}] doesn't exist"
          end
          domain = registrant[domainHeader]
          unless domain
            pp registrant
            throw "Can't find header #{domainHeader} in registrant #{dup}'s data #{registrant}"
          end
          
          existingDomain = csv_map[first][domainHeader]
          if !existingDomain.include?(domain)
            csv_map[first][domainHeader] += SeOpenData::CSV::Standard::V1::SubFieldSeparator + domain
          end
          # remove the duplicates from the map (this loop keeps only the first duplicate entry)
          
          csv_map.delete(dup)
        end
      end

      return duplicate_by_fields
    end

    def self.write_standard_csv(csv_out, csv_map, headers, nameHeader, addr_csv_original)
      headersOutput = false
      csv_map.each do |key, row|
        unless headersOutput
          csv_out << headers
          headersOutput = true
        end
        #row.id to identify orig row
        #row[:addr] = original[:addr]

        #This is a quick fix
        #TODO: FIX ME
        id = row["Identifier"]
        orig_addr_entry = addr_csv_original[[id]]

        if orig_addr_entry
          row["Street Address"] = orig_addr_entry["Street Address"]
          row["Locality"] = orig_addr_entry["Locality"]
          row["Region"] = orig_addr_entry["Region"]
          if row["Postcode"] == "" || !row["Postcode"]
            row["Postcode"] = orig_addr_entry["Postcode"]
          end
        end
        # Fix any entries that have no name
        if !row[nameHeader]
          row[nameHeader] = "N/A"
        end
        csv_out << row.values
      end
    end      

    def self.munge_dupes(csv_in, duplicate_by_fields, keys)
      flat_dups = duplicate_by_fields.clone.flatten(1)

      headers = nil
      csv_in.each do |row|
        unless headers
          headers = row.headers
        end
        key = keys.map { |k| row[k] }

        next unless flat_dups.include?(key)

        #replace all
        duplicate_by_fields.each do |subarray_of_dups|
          subarray_of_dups.map! { |dup| dup == key ? row : dup }
        end

        #rm key so it's skipped next time
        flat_dups.delete(key)

        break unless flat_dups.length > 0
      end

      return headers
    end
                 
    
    # Merge domains and de-duplicate rows of CSV (primarily for dotcoop).
    #
    # A duplicate is defined as having the same keys as a previous row
    #
    # OR
    #
    # The same fields as another row
    #
    # TODO - this should really take the field to merge as an argument so
    # it can be used by any other project that needs fields merging
    #
    # TODO separate field merging into different module
    #
    # @param input_io          Input CSV (must have headers)
    # @param output_io         CSV with duplicates removed
    # @param error_io          CSV containing duplicates (no headers)
    # @param reports_dir       directory into which to write report documents
    # @param keys              Array of column headings that make up the unique key
    # @param domainHeader      Header name for the domain
    # @param nameHeader        Header name for the name
    # @param original_csv      Original csv before geocoding. Must have the same schema!
    def CSV.merge_and_de_duplicate(
      input_io,
      output_io,
      error_io,
      reports_dir,
      keys,
      domainHeader,
      nameHeader,
      original_csv = nil
    )

      csv_opts = {headers: true}
      csv_in = ::CSV.new(input_io, **csv_opts)
      csv_out = ::CSV.new(output_io)
      csv_err = ::CSV.new(error_io)


      # Since some ids for the same coop are sometimes different,
      # we use all other fields (except the domain and the id)
      # to identify duplicate coop entries. We do this by building a map (string -> row)
      # the key of which is composed of all the other fields.
      # Some of the fields though might have some misspelled data, to catch that we can implement
      # fuzzy hashing, and hash the string key using Soundex or another algorithm
      addr_csv_original = mk_addr_csv_original(original_csv, csv_opts, keys)

      # csv_in should be the original document before geo uniformication
      
      duplicate_by_ids, headers = mk_duplicate_by_ids(domainHeader, keys, csv_in)
      
      # Since we can't be certain that the id will run lexicographically we need
      # to loop through the original data once and build a hashmap of the csv
      # with multiple domains moved into a single field.
      csv_map, name_map = mk_csv_map_etc(domainHeader, duplicate_by_ids, keys)
      
      field_map = munge_name_map(name_map)

      # filter duplicates by all other fields
      # merge rows that have duplicated data for all fields (except id and domain)
      duplicate_by_fields = mk_duplicate_by_fields(domainHeader, field_map, csv_map)

      write_standard_csv(csv_out, csv_map, headers, nameHeader, addr_csv_original)

      #print documents
      #duplicate_by_fields currently holds an array of arrays. [[key,key],[key,key]]
      #replace each key with it's corresponding row
      #TODO probably could be done better


      #csv_in should be the original document before geo unifornication
      original_csv_in = if original_csv != nil
                          ::CSV.read(original_csv, **csv_opts)
                        else
                          csv_in.rewind
                          csv_in
                        end

      headers3 = munge_dupes(original_csv_in, duplicate_by_fields, keys)

      err_doc_client = SeOpenData::Utils::ErrorDocumentGenerator.new("Duplicates DotCoop Title Page", "The process of importing data from DotCoop requires us to undergo several stages of data cleanup, fixing and rejecting some incompatible data that we cannot interpret.

        The following documents describe the 3 stages of processing and lists the corrections and decisions made.
        
        These documents make it clear how SEA is interpreting the DotCoop data and can be used by DotCoop to suggest corrections they can make to the source data.
        
        [We can provide these reports in other formats, csv, json etc. as requested, which may assist you using the data to correct the source data.]", nameHeader, domainHeader, headers3,
                                                                     output_dir: reports_dir)

      if original_csv != nil
        err_doc_client.add_similar_entries_fields_after_geo_uniform("Duplicates by Field after address cleaning with Geocoding service", "There are still some potential duplicates to find.

          A geocoding service is used to identify a more standard and sometimes more complete address for each domain. 
          The process of identifying potential duplicates using this cleaner data is repeated.  
          
          This ‘corrected’ address will be noted in the report and used in the database.
          
          
          geodups will list 
            - groups with different RegistrantIDs but identical or very similar names and addresses, noting that they will be considered the same co-op. Only one RegistrantID will be chosen to represent all the domains in this group from here on. A chosen name and corrected address will identified.", duplicate_by_fields)
      else
        err_doc_client.add_similar_entries_fields("Duplicates by Field before Geocoding", "The next stage is to organise domains into groups which have very similar names and addresses but different RegistrantIDs. This is done by using a fuzzy string comparison on the names and addresses.  


          fielddups will list 
            - the groups with different RegistrantIDs but identical or very similar names and addresses, noting that they will be considered the same co-op. Only one RegistrantID and one name and address will be chosen to represent all the domains in this group from here on. 
           ", duplicate_by_fields)
      end

      dup_ids = duplicate_by_ids.values.select { |a| a.length > 1 }

      # will not overwrite the second time since dup ids should be empty
      err_doc_client.add_similar_entries_id("Identical by RegistrantIDs", "All domains registered with the same RegistrantID are considered the same organisation.

        If there are small differences in the names or addresses registered with the same ID, we pick one of them and that is used for all the others.
         
        If there are larger differences, we cannot interpret which is correct, so we need this to be corrected at source, and none of this data will be included in the map.
        
        idsdups will list 
          - the groups with identical RegistrantIDs, names and addresses, noting that they will be considered the same co-op, with no corrections required
          - all the groups with identical RegistrantIDs but slight differences in name and/or address and display the name and address chosen to be used by all.
          - all the groups with identical RegistrantIDs but significantly different names and/or address, noting that they will not be included in the database.", dup_ids)
    end
  end
end
