package io.joern.traceextension

import better.files._
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.CpgPass
import flatgraph.DiffGraphBuilder
import io.shiftleft.semanticcpg.layers.{
  LayerCreator,
  LayerCreatorContext,
  LayerCreatorOptions
}
import io.shiftleft.semanticcpg.language._
import scala.io.Source
import upickle.default._

object TraceExtension {

  /**
    * This is the extension's official name as shown in the table
    * obtained when running `run` on the Joern shell.
    */
  val overlayName = "Trace Extension"

  /**
    * A short description shown in the table obtained when
    * running `run` on the Joern shell.
    */
  val description =
    "Augments CPG with dynamic trace information (TRACE_CALL edges and BeenTraced properties)"

  /**
    * Default options initialized to defaults. This object will be made
    * accessible to the user via `opts.traceextension`.
    * Both file paths are optional - at least one should be set before running the extension.
    */
  def defaultOpts = TraceExtensionOpts("", "")
}

/**
  * Options can be passed to the extension via a custom options
  * class that derives from `LayerCreatorOptions`. In our case,
  * we use the option class below to hand the paths to the trace
  * JSON files from the user to the extension.
  * 
  * @param pathToBeenTracedFile Path to JSON file containing list of function names for BeenTraced property (optional)
  * @param pathToTraceCallFile Path to JSON file containing call relationships in "caller -> callee" format (optional)
  */
case class TraceExtensionOpts(var pathToBeenTracedFile: String, var pathToTraceCallFile: String)
    extends LayerCreatorOptions {}

class TraceExtension(options: TraceExtensionOpts) extends LayerCreator {
  override val overlayName: String = TraceExtension.overlayName
  override val description: String = TraceExtension.description
  
  // Delimiter used to separate caller and callee in call relation strings
  private val CALL_RELATION_DELIMITER = "->"

  /**
    * This method is executed when the user issues the command
    * `run.traceextension`.
    */
  override def create(context: LayerCreatorContext): Unit = {
    val cpg = context.cpg
    new ApplyTraceDataPass(cpg).createAndApply()
  }

  private class ApplyTraceDataPass(cpg: Cpg) extends CpgPass(cpg) {
    override def run(builder: DiffGraphBuilder): Unit = {
      val startTime = System.currentTimeMillis()
      
      // Validate that at least one file path is provided
      if (options.pathToBeenTracedFile.isEmpty && options.pathToTraceCallFile.isEmpty) {
        println("[!] No trace files specified. Use:")
        println("    opts.traceextension.pathToBeenTracedFile = \"/path/to/beentraced.json\"")
        println("    opts.traceextension.pathToTraceCallFile = \"/path/to/tracecall.json\"")
        return
      }
      
      // Process BeenTraced file if provided
      var beenTracedCount = 0
      var beenTracedDuration = 0L
      if (options.pathToBeenTracedFile.nonEmpty) {
        val beenTracedFile = File(options.pathToBeenTracedFile)
        if (!beenTracedFile.exists) {
          println(s"[!] BeenTraced file not found: ${options.pathToBeenTracedFile}")
        } else {
          println(s"[*] Reading BeenTraced functions from ${options.pathToBeenTracedFile}")
          val beenTracedStartTime = System.currentTimeMillis()
          val functionNames = parseFunctionListJson(beenTracedFile)
          println(s"[*] Found ${functionNames.length} functions to mark as BeenTraced")
          
          functionNames.foreach { funcName =>
            cpg.method.name(funcName).foreach { method =>
              builder.setNodeProperty(method, "BeenTraced", true)
              beenTracedCount += 1
            }
          }
          beenTracedDuration = System.currentTimeMillis() - beenTracedStartTime
          println(s"[*] Marked ${beenTracedCount} method nodes with BeenTraced property")
        }
      }
      
      // Process TRACE_CALL file if provided
      var edgesAdded = 0
      var edgesSkipped = 0
      var traceCallDuration = 0L
      if (options.pathToTraceCallFile.nonEmpty) {
        val traceCallFile = File(options.pathToTraceCallFile)
        if (!traceCallFile.exists) {
          println(s"[!] TRACE_CALL file not found: ${options.pathToTraceCallFile}")
        } else {
          println(s"[*] Reading TRACE_CALL relationships from ${options.pathToTraceCallFile}")
          val traceCallStartTime = System.currentTimeMillis()
          val callRelations = parseCallRelationsJson(traceCallFile)
          println(s"[*] Found ${callRelations.length} call relationships")
          
          callRelations.zipWithIndex.foreach { case (relation, index) =>
            val parts = relation.split(CALL_RELATION_DELIMITER).map(_.trim)
            if (parts.length == 2) {
              val callerName = parts(0)
              val calleeName = parts(1)
              
              val callerMethods = cpg.method.name(callerName).l
              val calleeMethods = cpg.method.name(calleeName).l
              
              if (callerMethods.isEmpty || calleeMethods.isEmpty) {
                edgesSkipped += 1
                if (callerMethods.isEmpty) {
                  println(s"[!] Warning: Caller method '${callerName}' not found in CPG (entry ${index})")
                }
                if (calleeMethods.isEmpty) {
                  println(s"[!] Warning: Callee method '${calleeName}' not found in CPG (entry ${index})")
                }
              } else {
                // Add edge only if both methods exist
                callerMethods.foreach { callerMethod =>
                  calleeMethods.foreach { calleeMethod =>
                    builder.addEdge(callerMethod, calleeMethod, "TRACE_CALL", index)
                    edgesAdded += 1
                  }
                }
              }
            } else {
              println(s"[!] Warning: Invalid call relation format at entry ${index}: ${relation}")
            }
          }
          traceCallDuration = System.currentTimeMillis() - traceCallStartTime
          println(s"[*] Added ${edgesAdded} TRACE_CALL edges (skipped ${edgesSkipped} due to missing methods)")
        }
      }

      val totalDuration = System.currentTimeMillis() - startTime

      println(s"[+] Successfully applied trace data to CPG")
      println(s"[*] Performance Summary:")
      if (options.pathToBeenTracedFile.nonEmpty) {
        println(s"    - Adding BeenTraced properties: ${beenTracedDuration} ms (${beenTracedCount} methods)")
      }
      if (options.pathToTraceCallFile.nonEmpty) {
        println(s"    - Adding TRACE_CALL edges: ${traceCallDuration} ms (${edgesAdded} edges, ${edgesSkipped} skipped)")
      }
      println(s"    - Total execution time: ${totalDuration} ms")
    }

    /**
      * Parse JSON file containing a simple list of function names.
      * Used for BeenTraced property marking.
      */
    private def parseFunctionListJson(file: File): List[String] = {
      val content = file.contentAsString
      read[List[String]](content)
    }

    /**
      * Parse JSON file containing call relationships in "caller -> callee" format.
      * Used for TRACE_CALL edge creation.
      */
    private def parseCallRelationsJson(file: File): List[String] = {
      val content = file.contentAsString
      read[List[String]](content)
    }
  }


}
