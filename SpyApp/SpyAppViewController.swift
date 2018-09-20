import UIKit

class SpyAppViewController: UIViewController, UITextFieldDelegate {

    @IBOutlet weak var messageTextField: UITextField!
    @IBOutlet weak var secretTextField: UITextField!
    @IBOutlet weak var outputTextField: UILabel!
    
    @IBOutlet weak var cipherSegmentedControl: UISegmentedControl!
    @IBOutlet weak var encodeButton: UIButton!
    @IBOutlet weak var decryptButton: UIButton!
    @IBOutlet weak var clearButton: UIButton!
    @IBOutlet weak var copyButton: UIButton!
    
    let factory = CipherFactory()
    var cipher: Cipher!
    let segmentTitles = ["cesar", "alphacesar", "ftn", "ftn2"]
    
    override func viewDidLoad() {

        super.viewDidLoad()

        // control styling
        cipherSegmentedControl.layer.cornerRadius = 10.0
        cipherSegmentedControl.layer.borderWidth = 1.0
        cipherSegmentedControl.layer.masksToBounds = true
        encodeButton.layer.cornerRadius = 10.0
        decryptButton.layer.cornerRadius = 10.0
        clearButton.layer.cornerRadius = 10.0
        copyButton.layer.cornerRadius = 10.0
        
        // initialize segment selection
        let segmentIndex = 0
        let key = segmentTitles[segmentIndex]
        cipher = factory.cipher(for: key)

    }
    
    @IBAction func cipherSegmentSelected(_ sender: UISegmentedControl) {
        let segmentIndex = cipherSegmentedControl.selectedSegmentIndex
        let key = segmentTitles[segmentIndex]
        cipher = factory.cipher(for: key)
    }

    @IBAction func encodeButtonPressed(_ sender: UIButton) {
        outputTextField.text = "" // clear output first
        let plaintext = messageTextField.text!
        let secret = self.secretTextField.text!
        
        if cipher != nil {
            outputTextField.text = cipher.encode(plaintext, secret: secret)
        } else {
            outputTextField.text = CipherMessage.noCipherSelected
        }
    }
    
    @IBAction func decryptButtonPressed(_ sender: UIButton) {
        outputTextField.text = "" // clear output first
        let plaintext = messageTextField.text!
        let secret = self.secretTextField.text!
        
        if cipher != nil {
            outputTextField.text = cipher.decrypt(plaintext, secret: secret)
        } else {
            outputTextField.text = CipherMessage.noCipherSelected
        }
    }

    @IBAction func clearButtonPressed(_ sender: UIButton) {
        messageTextField.text = ""
        secretTextField.text = ""
        outputTextField.text = ""
        view.endEditing(true)
    }

    @IBAction func onTap(_ sender: Any) {
        view.endEditing(true)
    }
    
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        messageTextField.resignFirstResponder()
        return true
    }
    
    @IBAction func copyButtonPressed(_ sender: UIButton) {
        UIPasteboard.general.string = outputTextField.text
    }
    
    
}

