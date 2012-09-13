(ns clj-mifare-pass.gui
  (:import
   [javax.swing JLabel JButton JPanel JFrame])
  (:use [seesaw core mig]
        [clj-mifare-pass.pass]))


(native!)

(def key-a-text-field (text ""))
(def key-b-text-field (text ""))
(def d-key-a-field (text ""))
(def d-key-b-field (text ""))
(def mifare-passwd-field (text ""))


(defn form-content []
  (mig-panel :constraints ["wrap 3", "[right]"]
             :items [
                     [ "Input: (Key A and Key B length should be 6 bytes)"  "split, span, gaptop 10"]
                     [ :separator                                           "growx, wrap, gaptop 10"]
                     [ "Key A:"                                             "gap 10"]
                     [ key-a-text-field                                     "growx, wrap"]
                     [ "Key B:"                                             "gap 10"]
                     [ key-b-text-field                                     "growx, wrap"]
                     [ "Output:"                                            "split, span, gaptop 10"]
                     [ :separator                                           "growx, wrap, span, gaptop 10"]
                     [ "DKey A:"                                            "gap 10"]
                     [ d-key-a-field                                        "growx, wrap"]
                     [ "DKey B:"                                            "gap 10"]
                     [ d-key-b-field                                        "growx, wrap"]
                     [ "Mifare password:"                                   "gap 10"]
                     [ mifare-passwd-field                                  "growx, wrap"]
                     [ :separator                                           "growx, wrap, span, gaptop 10"]
                     [ (button :id :calculate :text "Calculate")            "gap 10"]
                     [ (button :id :close :text "Close")                    "gap 10, wrap"]
                     ]))


(defn add-behaviours[root]
  (listen (select root [:#calculate])
          :action (fn [e]
                    (let [key-a-str (text key-a-text-field)
                          key-b-str (text key-b-text-field)]
                      (cond (not= (.length key-a-str) 12) (alert "Wrong Key A length!")
                            (not= (.length key-b-str) 12) (alert "Wrong Key B length!")
                            :else (let [d-key-a (get-d-key-a (hexstr2bytes key-a-str))
                                        d-key-b (get-d-key-b (hexstr2bytes key-b-str))
                                        mifare-pass (get-mifare-pass d-key-a d-key-b)]
                                    (text! d-key-a-field (bytes2hexstr d-key-a))
                                    (text! d-key-b-field (bytes2hexstr d-key-b))
                                    (text! mifare-passwd-field (bytes2hexstr mifare-pass)))))))
  (listen (select root [:#close]) :action (fn [e] (dispose! root)))
  root)


(defn show-form [& args]
  (invoke-later
    (->
     (frame :title "Mifare Password calculator"
            :content (form-content)
            :resizable? true
            :on-close :exit)
     add-behaviours
     pack!
     show!)))