package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"

	"cloud.google.com/go/bigtable"
	"cloud.google.com/go/storage"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/olivere/elastic"
	"google.golang.org/api/option"
)

const (
	POST_INDEX = "post" // POST is db in elastic search
	POST_TYPE  = "post"
	DISTANCE   = "200km"

	// Needs to update this URL if you deploy it to cloud.
	ES_URL          = "http://104.196.52.199:9200"
	BUCKET_NAME     = "es_image_store"
	ENABLE_BIGTABLE = false
	API_PREFIX      = "/api/v1"
)

type Location struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

type Post struct {
	// `json:"user"` is for the json parsing of this User field. Otherwise, by default it's 'User'.
	User     string   `json:"user"`
	Message  string   `json:"message"`
	Location Location `json:"location"`
	Url      string   `json:"url"`
	Type     string   `json:"type"`
	Face     float64  `json:"face"`
}

const (
	INDEX = "around"
	TYPE  = "post"
	// Needs to update
	//PROJECT_ID = "around-xxx"
	//BT_INSTANCE = "around-post"
	// Needs to update this URL if you deploy it to cloud.

)

var (
	mediaTypes = map[string]string{
		".jpeg": "image",
		".jpg":  "image",
		".gif":  "image",
		".png":  "image",
		".mov":  "video",
		".mp4":  "video",
		".avi":  "video",
		".flv":  "video",
		".wmv":  "video",
	}
)

func main() {
	fmt.Println("started-service")
	createIndexIfNotExist()

	//if token can be decoded
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return []byte(mySigningKey), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
	})

	r := mux.NewRouter()

	r.Handle(API_PREFIX+"/post", jwtMiddleware.Handler(http.HandlerFunc(handlerPost))).Methods("POST", "OPTIONS")
	r.Handle(API_PREFIX+"/search", jwtMiddleware.Handler(http.HandlerFunc(handlerSearch))).Methods("GET", "OPTIONS")
	r.Handle(API_PREFIX+"/cluster", jwtMiddleware.Handler(http.HandlerFunc(handlerCluster))).Methods("GET", "OPTIONS")

	r.Handle(API_PREFIX+"/login", http.HandlerFunc(handlerLogin)).Methods("POST", "OPTIONS")
	r.Handle(API_PREFIX+"/signup", http.HandlerFunc(handlerSignup)).Methods("POST", "OPTIONS")

	// Backend endpoints.
	http.Handle(API_PREFIX+"/", r)
	// Frontend endpoints.
	http.Handle("/", http.FileServer(http.Dir("build")))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handlerPost(w http.ResponseWriter, r *http.Request) {
	// Parse from body of request to get a json object.
	fmt.Println("Received one post request")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")

	//read from token, FE no need to transfer any other info
	// "user" is a field in request, i.e., token
	user := r.Context().Value("user")
	claims := user.(*jwt.Token).Claims
	username := claims.(jwt.MapClaims)["username"]

	//formvalue is get value, formfile is get file
	lat, _ := strconv.ParseFloat(r.FormValue("lat"), 64)
	lon, _ := strconv.ParseFloat(r.FormValue("lon"), 64)

	// //post from fe to Post
	// decoder := json.NewDecoder(r.Body)
	// var p Post
	// if err := decoder.Decode(&p); err != nil {
	// 	// wrong post datatype, client's fault, badrequest
	// 	http.Error(w, "Cannot decode post data from client", http.StatusBadRequest)
	// 	fmt.Printf("Cannot decode post data from client %v.\n", err)
	// 	return
	// }

	//cannot decode, we have file
	//new obj pointer, so no extra copy for passing efficiency,
	p := &Post{
		//username is got from token
		User:    username.(string),
		Message: r.FormValue("message"),
		Location: Location{
			Lat: lat,
			Lon: lon,
		},
	}

	id := uuid.New().String() //we don't need id, just create an arbitrary unique one for parameter

	//now get file
	file, _, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "Image is not available", http.StatusBadRequest)
		fmt.Printf("Image is not available %v.\n", err)
		return
	}
	attrs, err := saveToGCS(file, BUCKET_NAME, id)
	if err != nil {
		http.Error(w, "Failed to save image to GCS", http.StatusInternalServerError)
		fmt.Printf("Failed to save image to GCS %v.\n", err)
		return
	}

	im, header, _ := r.FormFile("image")
	defer im.Close()
	suffix := filepath.Ext(header.Filename)

	// Client needs to know the media type so as to render it.
	if t, ok := mediaTypes[suffix]; ok {
		p.Type = t
	} else {
		p.Type = "unknown"
	}
	// ML Engine only supports jpeg.
	if suffix == ".jpeg" {
		if score, err := annotate(im); err != nil {
			http.Error(w, "Failed to annotate the image", http.StatusInternalServerError)
			fmt.Printf("Failed to annotate the image %v\n", err)
			return
		} else {
			p.Face = score
		}
	}

	p.Url = attrs.MediaLink

	err = saveToES(p, id)
	if err != nil {
		http.Error(w, "Failed to save post to ElasticSearch", http.StatusInternalServerError)
		fmt.Printf("Failed to save post to ElasticSearch %v.\n", err)
		return
	}
	fmt.Printf("Saved one post to ElasticSearch: %s", p.Message)

	if ENABLE_BIGTABLE {
		saveToBigTable(p, id)
	}

}

func handlerSearch(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received one request for search")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")

	lat, _ := strconv.ParseFloat(r.URL.Query().Get("lat"), 64)
	lon, _ := strconv.ParseFloat(r.URL.Query().Get("lon"), 64)
	// range is optional
	ran := DISTANCE
	if val := r.URL.Query().Get("range"); val != "" {
		ran = val + "km"
	}

	posts, err := readFromES(lat, lon, ran)
	if err != nil {
		http.Error(w, "Failed to read post from ElasticSearch", http.StatusInternalServerError)
		fmt.Printf("Failed to read post from ElasticSearch %v.\n", err)
		return
	}
	//post to json
	js, err := json.Marshal(posts)
	if err != nil {
		http.Error(w, "Failed to parse posts into JSON format", http.StatusInternalServerError)
		fmt.Printf("Failed to parse posts into JSON format %v.\n", err)
		return
	}

	w.Write(js)
}

func createIndexIfNotExist() {
	//use false for external ip, cuz db api is only exposed to internal
	client, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
	if err != nil {
		panic(err)
	}
	//index -> db, background() is go's go-routine control
	exists, err := client.IndexExists(POST_INDEX).Do(context.Background())
	if err != nil {
		panic(err)
	}

	if !exists {
		// generate an es schema, mappings(table), properties(field/col), type(2d-tree) are key work in es
		mapping := `{
			  "mappings": {
				  "post": {
					  "properties": {
						  "location": {
							  "type": "geo_point"
						  }
					  }
				  }
			  }
		  }`
		//create schema
		// in GO, we cannot create a var without using it, so use _
		_, err = client.CreateIndex(POST_INDEX).Body(mapping).Do(context.Background())
		if err != nil {
			panic(err)
		}
	}

	exists, err = client.IndexExists(USER_INDEX).Do(context.Background())
	if err != nil {
		panic(err)
	}

	if !exists {
		_, err = client.CreateIndex(USER_INDEX).Do(context.Background())
		if err != nil {
			panic(err)
		}
	}

}

// Save a post to ElasticSearch
func saveToES(post *Post, id string) error {
	client, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
	if err != nil {
		return err
	}

	_, err = client.Index().
		Index(POST_INDEX).
		Type(POST_TYPE).
		Id(id).
		BodyJson(post).
		Refresh("wait_for").
		Do(context.Background())
	if err != nil {
		return err
	}

	fmt.Printf("Post is saved to index: %s\n", post.Message)
	return nil
}

func saveToBigTable(p *Post, id string) {
	ctx := context.Background()
	bt_client, err := bigtable.NewClient(ctx, "acoustic-field-225722", "around-post", option.WithCredentialsFile("Around-46012d30765a.json"))
	if err != nil {
		panic(err)
		return
	}

	tbl := bt_client.Open("post")
	mut := bigtable.NewMutation()
	t := bigtable.Now()
	mut.Set("post", "user", t, []byte(p.User))
	mut.Set("post", "message", t, []byte(p.Message))
	mut.Set("location", "lat", t, []byte(strconv.FormatFloat(p.Location.Lat, 'f', -1, 64)))
	mut.Set("location", "lon", t, []byte(strconv.FormatFloat(p.Location.Lon, 'f', -1, 64)))

	err = tbl.Apply(ctx, id, mut)
	if err != nil {
		panic(err)
		return
	}
	fmt.Printf("Post is saved to BigTable: %s\n", p.Message)

}

//ran is search radius, return two vals, []Post if success, or error
func readFromES(lat, lon float64, ran string) ([]Post, error) {
	client, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
	if err != nil {
		return nil, err
	}

	//query according to field "locatoin"
	query := elastic.NewGeoDistanceQuery("location")
	query = query.Distance(ran).Lat(lat).Lon(lon)

	searchResult, err := client.Search().
		Index(POST_INDEX).
		Query(query).
		Pretty(true).
		Do(context.Background())
	if err != nil {
		return nil, err
	}

	// searchResult is of type SearchResult and returns hits, suggestions,
	// and all kinds of other information from Elasticsearch.
	fmt.Printf("Query took %d milliseconds\n", searchResult.TookInMillis)

	// Each is a convenience function that iterates over hits in a search result.
	// It makes sure you don't need to check for nil values in the response.
	// However, it ignores errors in serialization. If you want full control
	// over iterating the hits, see below.
	var ptyp Post
	var posts []Post
	//first we need to find all that can be converted to post
	for _, item := range searchResult.Each(reflect.TypeOf(ptyp)) {
		if p, ok := item.(Post); ok {
			posts = append(posts, p)
		}
	}

	return posts, nil
}

//save img, return pointer * without copy
func saveToGCS(r io.Reader, bucketName, objectName string) (*storage.ObjectAttrs, error) {
	ctx := context.Background()

	// Creates a client.
	client, err := storage.NewClient(ctx, option.WithCredentialsFile("Around-46012d30765a.json"))

	if err != nil {
		return nil, err
	}

	bucket := client.Bucket(bucketName)
	if _, err := bucket.Attrs(ctx); err != nil {
		return nil, err
	}

	object := bucket.Object(objectName)
	wc := object.NewWriter(ctx)
	if _, err = io.Copy(wc, r); err != nil {
		return nil, err
	}
	if err := wc.Close(); err != nil {
		return nil, err
	}

	if err = object.ACL().Set(ctx, storage.AllUsers, storage.RoleReader); err != nil {
		return nil, err
	}

	attrs, err := object.Attrs(ctx)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Image is saved to GCS: %s\n", attrs.MediaLink)
	return attrs, nil
}

func handlerCluster(w http.ResponseWriter, r *http.Request) {
	// Parse from body of request to get a json object.
	fmt.Println("Received one post request")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")

	//fe send OPTION to handle if endpoint available
	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != "GET" {
		return
	}

	term := r.URL.Query().Get("term")

	// Create a client
	client, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
	if err != nil {
		http.Error(w, "ES is not setup", http.StatusInternalServerError)
		fmt.Printf("ES is not setup %v\n", err)
		return
	}

	// Range query.
	// For details, https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-range-query.html
	q := elastic.NewRangeQuery(term).Gte(0.9)

	searchResult, err := client.Search().
		Index(POST_INDEX).
		Query(q).
		Pretty(true).
		Do(context.Background())
	if err != nil {
		// Handle error
		m := fmt.Sprintf("Failed to query ES %v", err)
		fmt.Println(m)
		http.Error(w, m, http.StatusInternalServerError)
	}

	// searchResult is of type SearchResult and returns hits, suggestions,
	// and all kinds of other information from Elasticsearch.
	fmt.Printf("Query took %d milliseconds\n", searchResult.TookInMillis)
	// TotalHits is another convenience function that works even when something goes wrong.
	fmt.Printf("Found a total of %d post\n", searchResult.TotalHits())

	// Each is a convenience function that iterates over hits in a search result.
	// It makes sure you don't need to check for nil values in the response.
	// However, it ignores errors in serialization.
	var typ Post
	var ps []Post
	for _, item := range searchResult.Each(reflect.TypeOf(typ)) {
		p := item.(Post)
		ps = append(ps, p)

	}
	js, err := json.Marshal(ps)
	if err != nil {
		m := fmt.Sprintf("Failed to parse post object %v", err)
		fmt.Println(m)
		http.Error(w, m, http.StatusInternalServerError)
		return
	}

	w.Write(js)
}
