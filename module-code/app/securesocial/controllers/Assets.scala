package securesocial.controllers

import javax.inject.Inject

import controllers.{ AssetsBuilder, AssetsMetadata }
import play.api.http.HttpErrorHandler

class Assets @Inject() (errorHandler: HttpErrorHandler, meta: AssetsMetadata) extends AssetsBuilder(errorHandler, meta)